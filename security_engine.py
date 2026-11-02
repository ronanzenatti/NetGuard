"""
NetGuard - Motor de Análise de Cibersegurança, Heurística e Inteligência de Rede
Fornece:
1. Classificação de risco (Seguro, Telemetria/Atenção, Suspeito/Crítico)
2. Dicionário de processos (Explicação para Leigos + Contexto Técnico para Estudantes)
3. Identificação de Destinos (LAN, Loopback, Provedores Globais, rDNS e GeoIP/ASN assíncrono)
4. Detecção de Masquerading (Impostores de processos do Windows) e Portas Suspeitas
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import socket
import threading
import urllib.request
from dataclasses import dataclass
from typing import Callable, Dict, Optional, Tuple


@dataclass
class SecurityAnalysis:
    risk_level: str          # "SAFE", "TELEMETRY", "WARNING", "CRITICAL"
    risk_badge: str          # "🟢 Seguro", "🟡 Telemetria", "🟠 Atenção", "🔴 Suspeito"
    destination_org: str     # Ex: "🇺🇸 Google LLC", "🏠 Rede Local (Chromecast)"
    layman_title: str        # Resumo curto para leigo
    layman_explanation: str  # Explicação clara em português sobre o programa e a conexão
    layman_advice: str       # Recomendação clara se deve ou pode bloquear
    technical_notes: str     # Detalhes técnicos para estudantes/entusiastas de cibersegurança
    is_system_critical: bool # Se bloquear pode quebrar o sistema operacional


# ---------------- Base de Conhecimento de Processos Conhecidos ----------------
KNOWN_PROCESSES: Dict[str, dict] = {
    "sistema / kernel": {
        "title": "Núcleo do Sistema Operacional Windows (Kernel)",
        "layman": "É o coração do próprio Windows gerenciando comunicações básicas de rede e encerrando conexões antigas (TIME_WAIT).",
        "advice": "⛔ Nunca bloqueie: essencial para o funcionamento do computador e da internet.",
        "tech": "PID 0/4 (ntoskrnl.exe). Gerencia a pilha TCP/IP do Windows (tcpip.sys), sockets em TIME_WAIT e serviços SMB/NetBIOS.",
        "critical": True,
        "telemetry": False,
        "expected_paths": ["c:\\windows\\system32"],
    },
    "svchost.exe": {
        "title": "Host de Serviços do Windows (Service Host)",
        "layman": "Processo oficial do Windows responsável por rodar serviços internos como Windows Update, DNS, Horário do Sistema e Rede.",
        "advice": "⚠️ Não bloqueie o executável inteiro (pode parar a internet ou o Windows Update). Só bloqueie um IP específico se for telemetria.",
        "tech": "Container genérico de DLLs de serviço do Windows. Alvo clássico de MITRE ATT&CK T1036 (Masquerading) e T1055 (Process Injection). Deve SEMPRE residir em C:\\Windows\\System32 ou SysWOW64.",
        "critical": True,
        "telemetry": False,
        "expected_paths": ["c:\\windows\\system32", "c:\\windows\\syswow64"],
    },
    "mpdefendercoservice.exe": {
        "title": "Microsoft Defender Antivírus (Core Service)",
        "layman": "É o antivírus oficial do seu Windows verificando ameaças na nuvem e baixando novas vacinas de segurança.",
        "advice": "⛔ Não bloqueie: bloquear este processo reduz a proteção contra vírus do seu computador.",
        "tech": "Serviço de proteção em nuvem (MAPS / Microsoft Active Protection Service) do Windows Defender.",
        "critical": True,
        "telemetry": False,
        "expected_paths": ["c:\\programdata\\microsoft\\windows defender"],
    },
    "msmpeng.exe": {
        "title": "Motor Antimalware do Windows Defender",
        "layman": "Motor principal do antivírus nativo do Windows.",
        "advice": "⛔ Não bloqueie: mantém seu PC protegido contra malwares em tempo real.",
        "tech": "Microsoft Malware Protection Engine. Realiza consultas de reputação de hash via TLS (porta 443) na nuvem da Microsoft.",
        "critical": True,
        "telemetry": False,
        "expected_paths": ["c:\\programdata\\microsoft\\windows defender"],
    },
    "nvcontainer.exe": {
        "title": "NVIDIA Container (Serviços e Telemetria da Placa de Vídeo)",
        "layman": "Programa da sua placa de vídeo NVIDIA. Além de recursos do driver, ele frequentemente envia dados de uso (telemetria) e verifica atualizações em segundo plano.",
        "advice": "✅ Seguro bloquear se você não usa o GeForce Experience / NVIDIA App online e não quer enviar dados de uso para a NVIDIA.",
        "tech": "Container de processos da NVIDIA. Frequentemente estabelece sessões TLS para servidores Akamai/NVIDIA para telemetria e sincronização de perfis.",
        "critical": False,
        "telemetry": True,
        "expected_paths": ["c:\\program files\\nvidia corporation"],
    },
    "chrome.exe": {
        "title": "Navegador Google Chrome",
        "layman": "Seu navegador de internet. Cada aba aberta, extensão ou serviço do Google cria conexões para carregar sites e vídeos.",
        "advice": "ℹ️ Normal enquanto você navega. Se houver conexões estranhas com todas as abas fechadas, verifique suas extensões instaladas.",
        "tech": "Arquitetura multi-processo Chromium (Network Service utility process). Conexões UDP 443 indicam protocolo QUIC / HTTP/3; porta 8009 na LAN indica descoberta mDNS/Cast.",
        "critical": False,
        "telemetry": False,
        "expected_paths": ["c:\\program files\\google\\chrome", "c:\\program files (x86)\\google\\chrome"],
    },
    "msedge.exe": {
        "title": "Navegador Microsoft Edge",
        "layman": "Navegador padrão do Windows. Costuma manter conexões em segundo plano para notícias, sincronização e atualizações.",
        "advice": "✅ Seguro bloquear apenas se você não utiliza o Edge e quer impedir que ele consuma internet em segundo plano.",
        "tech": "Baseado em Chromium. Mantém conexões persistentes com MSN/Bing/Microsoft Edge Services mesmo em background se o Startup Boost estiver ativo.",
        "critical": False,
        "telemetry": True,
        "expected_paths": ["c:\\program files (x86)\\microsoft\\edge", "c:\\program files\\microsoft\\edge"],
    },
    "firefox.exe": {
        "title": "Navegador Mozilla Firefox",
        "layman": "Seu navegador de internet Mozilla Firefox carregando páginas e serviços web.",
        "advice": "ℹ️ Normal durante o uso do navegador.",
        "tech": "Processo principal/socket process do Gecko. Utiliza TLS 1.3 (TCP 443) e HTTP/3 (UDP 443).",
        "critical": False,
        "telemetry": False,
        "expected_paths": ["c:\\program files\\mozilla firefox"],
    },
    "code.exe": {
        "title": "Microsoft Visual Studio Code (Editor de Código)",
        "layman": "Editor de programação VS Code. Conecta-se à internet para baixar extensões, sincronizar configurações, usar IA (Copilot/Claude) e verificar atualizações.",
        "advice": "ℹ️ Normal para desenvolvedores. Pode ter IPs de telemetria bloqueados se desejar privacidade extra.",
        "tech": "Aplicação Electron/Node.js. Conexões frequentes para GitHub (185.199.x.x / 140.82.x.x), Azure e APIs de extensões.",
        "critical": False,
        "telemetry": False,
        "expected_paths": ["microsoft vs code"],
    },
    "agy.exe": {
        "title": "Google Antigravity (Assistente de IA & Desenvolvimento)",
        "layman": "Ferramenta de programação assistida por Inteligência Artificial que você está utilizando neste momento.",
        "advice": "⛔ Não bloqueie enquanto estiver utilizando o assistente.",
        "tech": "Cliente CLI/IDE que estabelece túneis HTTPS/gRPC (porta 443) com a infraestrutura do Google Cloud / Gemini API.",
        "critical": False,
        "telemetry": False,
        "expected_paths": [".gemini\\bin"],
    },
    "claude.exe": {
        "title": "Anthropic Claude Code (Agente de IA)",
        "layman": "Extensão/Agente de Inteligência Artificial Claude conectada aos servidores da Anthropic.",
        "advice": "ℹ️ Normal se você utiliza a extensão Claude no seu VS Code.",
        "tech": "Binário nativo da extensão Anthropic comunicando via TLS (443) com o bloco 160.79.104.0/24 (Anthropic).",
        "critical": False,
        "telemetry": False,
        "expected_paths": [".vscode\\extensions"],
    },
    "compattelrunner.exe": {
        "title": "Telemetria de Compatibilidade da Microsoft",
        "layman": "Serviço do Windows que coleta diagnósticos e dados de uso do seu PC para enviar à Microsoft.",
        "advice": "✅ Seguro bloquear se você preza por privacidade e não deseja enviar relatórios de telemetria à Microsoft.",
        "tech": "Microsoft Compatibility Telemetry. Costuma consumir disco/CPU e enviar pacotes de telemetria para servidores Vortex da Microsoft.",
        "critical": False,
        "telemetry": True,
        "expected_paths": ["c:\\windows\\system32"],
    },
    "diagtrack": {
        "title": "Experiências do Usuário Conectado e Telemetria",
        "layman": "Coletor de dados de diagnóstico e hábitos de uso do Windows.",
        "advice": "✅ Seguro bloquear para impedir envio de telemetria do Windows.",
        "tech": "Serviço Connected User Experiences and Telemetry (DiagTrack).",
        "critical": False,
        "telemetry": True,
        "expected_paths": ["c:\\windows\\system32"],
    },
    "onedrive.exe": {
        "title": "Microsoft OneDrive (Armazenamento em Nuvem)",
        "layman": "Sincroniza seus arquivos e fotos da pasta Documentos/Imagens com a nuvem da Microsoft.",
        "advice": "✅ Seguro bloquear caso você não utilize o backup na nuvem do OneDrive e não queira seus arquivos sincronizados online.",
        "tech": "Cliente de sincronização SkyDrive/OneDrive comunicando via HTTPS com blocos da Microsoft/Azure.",
        "critical": False,
        "telemetry": False,
        "expected_paths": ["microsoft\\onedrive"],
    },
    "spotify.exe": {
        "title": "Spotify (Streaming de Música)",
        "layman": "Aplicativo de música Spotify baixando áudio e procurando dispositivos na sua rede local (Spotify Connect).",
        "advice": "ℹ️ Normal durante o uso do Spotify.",
        "tech": "Utiliza HTTPS/TCP 4070/443 para streaming e UDP 5353/1900 na LAN para descoberta de alto-falantes inteligentes.",
        "critical": False,
        "telemetry": False,
        "expected_paths": ["spotify"],
    },
    "discord.exe": {
        "title": "Discord (Chat de Voz e Texto)",
        "layman": "Aplicativo de comunicação Discord mantendo chat e chamadas de voz ativas.",
        "advice": "ℹ️ Normal enquanto o Discord estiver aberto.",
        "tech": "Cliente Electron. Usa TCP 443 (Cloudflare) para sinalização/mensagens e portas UDP altas (50000-65535) para voz WebRTC.",
        "critical": False,
        "telemetry": False,
        "expected_paths": ["discord"],
    },
    "steam.exe": {
        "title": "Steam (Plataforma de Jogos Valve)",
        "layman": "Cliente da loja e biblioteca de jogos Steam verificando amigos online e atualizações de jogos.",
        "advice": "ℹ️ Normal enquanto a Steam estiver aberta.",
        "tech": "Comunica via TCP/UDP (portas 27015-27050 e 443) com a rede Steamworks/Akamai.",
        "critical": False,
        "telemetry": False,
        "expected_paths": ["steam"],
    },
}

# Processos críticos do Windows que NUNCA podem rodar fora de C:\Windows (Detecção de Masquerading)
STRICT_WINDOWS_PROCESSES = {
    "svchost.exe": ["c:\\windows\\system32", "c:\\windows\\syswow64"],
    "lsass.exe": ["c:\\windows\\system32"],
    "csrss.exe": ["c:\\windows\\system32"],
    "services.exe": ["c:\\windows\\system32"],
    "wininit.exe": ["c:\\windows\\system32"],
    "smss.exe": ["c:\\windows\\system32"],
    "spoolsv.exe": ["c:\\windows\\system32"],
    "taskhostw.exe": ["c:\\windows\\system32"],
    "dwm.exe": ["c:\\windows\\system32"],
    "explorer.exe": ["c:\\windows"],
}

# Portas frequentemente associadas a Backdoors, RATs, Trojans ou Mineração de Criptomoedas
SUSPICIOUS_PORTS: Dict[int, str] = {
    4444: "Porta clássica do Metasploit / Meterpreter (Reverse Shell)",
    1337: "Porta comumente usada por Backdoors / RATs (Leet port)",
    31337: "Porta clássica do Trojan Back Orifice / C2",
    6667: "Porta IRC (Frequentemente usada por Botnets para Comando e Controle)",
    6697: "Porta IRC TLS (Comum em Botnets)",
    3333: "Porta comum de pools de Mineração de Criptomoedas (Stratum)",
    14444: "Porta de Mineração de Monero (XMRig / CryptoMiner)",
    5555: "Android Debug Bridge (ADB) ou Pool de Mineração",
    23: "Telnet (Tráfego em texto puro sem criptografia - Alto Risco)",
    445: "SMB / Compartilhamento de Arquivos (Perigoso se conectado à Internet pública)",
    3389: "Área de Trabalho Remota (RDP - Alvo frequente de ataques de força bruta)",
}

# Explicação de Portas Comuns para Leigos e Estudantes
COMMON_PORTS_INFO: Dict[int, str] = {
    443: "HTTPS (Conexão Web Criptografada Segura via TLS/SSL)",
    80: "HTTP (Conexão Web Padrão sem criptografia)",
    53: "DNS (Tradução de nomes de sites para endereços IP)",
    123: "NTP (Sincronização automática do relógio do Windows)",
    1900: "UPnP / SSDP (Descoberta de dispositivos como Roteador e Smart TV na sua casa)",
    5353: "mDNS (Descoberta de dispositivos locais como Chromecast, Impressoras e Apple AirPlay)",
    8009: "Google Cast / Chromecast (Comunicação com Smart TV ou aparelho de mídia na sua rede Wi-Fi)",
    5228: "Google Play / Notificações Push do Google Chrome (GCM/FCM)",
    137: "NetBIOS Name Service (Identificação de computadores na rede doméstica Windows)",
    138: "NetBIOS Datagram Service (Compartilhamento na rede local Windows)",
    139: "NetBIOS Session Service (Compartilhamento de pastas na rede local)",
}

# Palavras-chave que indicam processos de telemetria / coleta de dados
TELEMETRY_KEYWORDS = (
    "telemetry",
    "diagtrack",
    "compattel",
    "crashhandler",
    "crashpad",
    "reporter",
    "updater",
    "nvcontainer",
    "ceip",
    "feedback",
)

# ---------------- Resolução Rápida de Provedores / Nuvens Conhecidas ----------------
KNOWN_IP_PREFIXES = [
    ("172.217.", "🇺🇸 Google LLC"),
    ("142.250.", "🇺🇸 Google LLC"),
    ("142.251.", "🇺🇸 Google LLC"),
    ("216.58.", "🇺🇸 Google LLC"),
    ("8.8.8.", "🇺🇸 Google DNS"),
    ("8.8.4.", "🇺🇸 Google DNS"),
    ("1.1.1.", "🇺🇸 Cloudflare DNS"),
    ("1.0.0.", "🇺🇸 Cloudflare DNS"),
    ("104.16.", "🇺🇸 Cloudflare, Inc."),
    ("104.17.", "🇺🇸 Cloudflare, Inc."),
    ("104.18.", "🇺🇸 Cloudflare, Inc."),
    ("104.21.", "🇺🇸 Cloudflare, Inc."),
    ("185.199.108.", "🇺🇸 GitHub / Fastly"),
    ("185.199.109.", "🇺🇸 GitHub / Fastly"),
    ("185.199.110.", "🇺🇸 GitHub / Fastly"),
    ("185.199.111.", "🇺🇸 GitHub / Fastly"),
    ("140.82.", "🇺🇸 GitHub, Inc."),
    ("199.232.", "🇺🇸 Fastly CDN (GitHub/Web)"),
    ("160.79.104.", "🇺🇸 Anthropic (Claude AI)"),
    ("57.144.", "🇺🇸 Meta Platforms (Facebook/WhatsApp)"),
    ("31.13.", "🇺🇸 Meta Platforms (Facebook/Instagram)"),
    ("157.240.", "🇺🇸 Meta Platforms (WhatsApp/Instagram)"),
    ("52.", "🇺🇸 Microsoft Corporation (Azure/Windows)"),
    ("20.", "🇺🇸 Microsoft Corporation (Azure)"),
    ("40.", "🇺🇸 Microsoft Corporation (Azure)"),
    ("13.107.", "🇺🇸 Microsoft Corporation"),
    ("204.79.197.", "🇺🇸 Microsoft (Bing/Edge)"),
    ("172.172.", "🇺🇸 Microsoft Azure Cloud"),
    ("4.228.", "🇧🇷 Microsoft Azure (Brasil)"),
    ("34.", "🇺🇸 Google Cloud Platform"),
    ("35.", "🇺🇸 Google Cloud Platform"),
    ("2.16.", "🌐 Akamai Technologies CDN"),
    ("2.17.", "🌐 Akamai Technologies CDN"),
    ("2.18.", "🌐 Akamai Technologies (NVIDIA/CDN)"),
    ("2.19.", "🌐 Akamai Technologies CDN"),
    ("2.20.", "🌐 Akamai Technologies CDN"),
    ("2.21.", "🌐 Akamai Technologies CDN"),
    ("2.22.", "🌐 Akamai Technologies CDN"),
    ("23.", "🌐 Akamai Technologies CDN"),
]


class IPIntelligenceCache:
    """Resolve e armazena em cache informações de IPs remotos sem travar a interface."""
    def __init__(self):
        self._cache: Dict[str, str] = {}
        self._rdns_cache: Dict[str, str] = {}
        self._pending: set[str] = set()
        self._lock = threading.Lock()

    def classify_ip_instant(self, ip_str: str, remote_port: str = "-") -> str:
        """Retorna imediatamente a organização/destino conhecido ou dispara resolução em background."""
        if not ip_str or ip_str in ("-", "0.0.0.0", "::", "*"):
            return "— (Aguardando Conexão)"

        if ip_str in self._cache:
            return self._cache[ip_str]

        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_loopback:
                res = "🏠 Loopback (Este Computador)"
                self._cache[ip_str] = res
                return res
            if ip_obj.is_multicast:
                res = "📡 Rede Local (Multicast/Descoberta)"
                self._cache[ip_str] = res
                return res
            if ip_obj.is_private or ip_obj.is_link_local:
                if str(remote_port) == "8009":
                    res = "🏠 Rede Local (Smart TV / Chromecast)"
                elif str(remote_port) in ("53", "80", "443") and ip_str.endswith(".1"):
                    res = "🏠 Seu Roteador / Gateway Wi-Fi"
                else:
                    res = "🏠 Dispositivo na sua Rede Local (Wi-Fi/LAN)"
                self._cache[ip_str] = res
                return res
        except ValueError:
            return "Desconhecido"

        # Verificar prefixos conhecidos de grandes empresas de tecnologia
        for prefix, org_name in KNOWN_IP_PREFIXES:
            if ip_str.startswith(prefix):
                self._cache[ip_str] = org_name
                return org_name

        # Disparar resolução assíncrona em background para IPs públicos desconhecidos
        self._trigger_async_lookup(ip_str)
        return "🌐 Servidor Externo (Identificando...)"

    def get_rdns(self, ip_str: str) -> str:
        """Retorna o hostname reverso se já estiver em cache."""
        return self._rdns_cache.get(ip_str, "Resolvendo DNS reverso...")

    def _trigger_async_lookup(self, ip_str: str):
        with self._lock:
            if ip_str in self._pending or len(self._pending) > 25:
                return
            self._pending.add(ip_str)

        t = threading.Thread(target=self._resolve_worker, args=(ip_str,), daemon=True)
        t.start()

    def _resolve_worker(self, ip_str: str):
        # 1. Tentar DNS Reverso (PTR)
        hostname = ""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip_str)
            self._rdns_cache[ip_str] = hostname
        except Exception:
            self._rdns_cache[ip_str] = "Sem registro PTR (rDNS)"

        # 2. Consultar API gratuita ip-api.com para País + ISP/Org
        try:
            url = f"http://ip-api.com/json/{ip_str}?fields=status,countryCode,country,org,isp"
            req = urllib.request.Request(url, headers={"User-Agent": "NetGuard-Security-Monitor/2.0"})
            with urllib.request.urlopen(req, timeout=2.5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                if data.get("status") == "success":
                    cc = data.get("countryCode", "")
                    org = data.get("org") or data.get("isp") or data.get("country", "Externo")
                    flag = self._country_code_to_flag(cc)
                    short_org = org[:32] + ("..." if len(org) > 32 else "")
                    self._cache[ip_str] = f"{flag} {short_org}"
                    return
        except Exception:
            pass

        # Fallback por hostname reverso
        if hostname:
            parts = hostname.split(".")
            domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
            self._cache[ip_str] = f"🌐 {domain}"
        else:
            self._cache[ip_str] = "🌐 Servidor Público Externo"

        with self._lock:
            self._pending.discard(ip_str)

    @staticmethod
    def _country_code_to_flag(cc: str) -> str:
        if not cc or len(cc) != 2:
            return "🌐"
        return chr(ord(cc[0].upper()) + 127397) + chr(ord(cc[1].upper()) + 127397)


ip_intel = IPIntelligenceCache()


def evaluate_connection_security(
    pid: Optional[int],
    process_name: str,
    exe_path: str,
    proto: str,
    local_ip: str,
    local_port: int,
    remote_ip: str,
    remote_port_str: str,
    status: str,
) -> SecurityAnalysis:
    """
    Analisa uma conexão combinando heurísticas de cibersegurança (caminho do binário,
    process masquerading, portas suspeitas, telemetria e reputação do destino).
    """
    proc_lower = (process_name or "").lower().strip()
    path_lower = (exe_path or "").lower().strip()

    try:
        remote_port = int(remote_port_str)
    except ValueError:
        remote_port = 0

    dest_org = ip_intel.classify_ip_instant(remote_ip, remote_port_str)
    port_desc = (
        COMMON_PORTS_INFO.get(remote_port)
        or COMMON_PORTS_INFO.get(local_port)
        or f"Porta de comunicação {remote_port or local_port} ({proto})"
    )

    # ---------------- 1. VERIFICAÇÃO CRÍTICA: Process Masquerading (Impostor de Sistema) ----------------
    if proc_lower in STRICT_WINDOWS_PROCESSES and path_lower and "acesso negado" not in path_lower and "não disponível" not in path_lower:
        valid_prefixes = STRICT_WINDOWS_PROCESSES[proc_lower]
        if not any(path_lower.startswith(prefix) for prefix in valid_prefixes):
            return SecurityAnalysis(
                risk_level="CRITICAL",
                risk_badge="🔴 Suspeito (Impostor)",
                destination_org=dest_org,
                layman_title=f"🚨 ALERTA: Falso processo '{process_name}' fora da pasta do Windows!",
                layman_explanation=(
                    f"O programa se chama '{process_name}' (que é um nome do Windows), mas está rodando em uma pasta suspeita: '{exe_path}'. "
                    "Malwares frequentemente usam nomes de arquivos do Windows para se esconder."
                ),
                layman_advice="🛑 RECOMENDAÇÃO URGENTE: Bloqueie este programa no Firewall imediatamente e encerre o processo!",
                technical_notes=(
                    f"[MITRE ATT&CK T1036 - Masquerading] Binário '{process_name}' executando fora de System32/Windows ({exe_path}). "
                    f"Conexão {proto} {local_ip}:{local_port} -> {remote_ip}:{remote_port_str} ({status})."
                ),
                is_system_critical=False,
            )

    # ---------------- 2. VERIFICAÇÃO CRÍTICA: Execução em Pastas Temporárias / Downloads ----------------
    suspicious_folders = ("\\appdata\\local\\temp\\", "\\downloads\\", "\\$recycle.bin\\", "\\users\\public\\")
    if any(folder in path_lower for folder in suspicious_folders) and remote_ip not in ("-", "127.0.0.1", "::1"):
        return SecurityAnalysis(
            risk_level="CRITICAL",
            risk_badge="🔴 Suspeito (Pasta Temp)",
            destination_org=dest_org,
            layman_title=f"⚠️ Programa rodando direto da pasta Temporária ou Downloads ({process_name})",
            layman_explanation=(
                f"Este executável está abrindo conexões com a internet a partir de '{exe_path}'. "
                "Programas legítimos instalados normalmente ficam na pasta 'Arquivos de Programas', não em pastas temporárias."
            ),
            layman_advice="⚠️ Se você não está instalando nada agora, bloqueie este programa no Firewall por segurança.",
            technical_notes=(
                f"[Heurística de Caminho Volátil] Executável em diretório temporário/Downloads realizando conexão externa. "
                f"Alvo: {remote_ip}:{remote_port_str} ({dest_org}). Porta: {port_desc}."
            ),
            is_system_critical=False,
        )

    # ---------------- 3. VERIFICAÇÃO DE PORTAS SUSPEITAS (Backdoors / Miners / RATs) ----------------
    flagged_port = SUSPICIOUS_PORTS.get(remote_port) or SUSPICIOUS_PORTS.get(local_port)
    if flagged_port and remote_ip not in ("-", "127.0.0.1", "::1") and not remote_ip.startswith("192.168."):
        return SecurityAnalysis(
            risk_level="CRITICAL",
            risk_badge="🔴 Porta de Risco",
            destination_org=dest_org,
            layman_title=f"⚠️ Conexão em porta de risco ({remote_port or local_port}): {flagged_port}",
            layman_explanation=(
                f"O programa '{process_name}' está utilizando uma porta frequentemente associada a invasões, acesso remoto ou mineração ({flagged_port})."
            ),
            layman_advice="🛑 Se você não reconhece esta atividade, bloqueie a conexão no Firewall imediatamente.",
            technical_notes=(
                f"[Alerta de Porta Sensível] {flagged_port}. Processo: {process_name} (PID {pid}). "
                f"Socket: {proto} {local_ip}:{local_port} -> {remote_ip}:{remote_port_str}."
            ),
            is_system_critical=False,
        )

    # ---------------- 4. CONSULTA À BASE DE PROCESSOS CONHECIDOS ----------------
    known = KNOWN_PROCESSES.get(proc_lower)
    if known:
        is_telemetry = known.get("telemetry", False)
        is_crit = known.get("critical", False)

        # Se for processo de telemetria conhecido ou conexão da Microsoft em background
        if is_telemetry:
            return SecurityAnalysis(
                risk_level="TELEMETRY",
                risk_badge="🟡 Telemetria / Dados",
                destination_org=dest_org,
                layman_title=known["title"],
                layman_explanation=f"{known['layman']}\n• Destino atual: {dest_org} ({port_desc}).",
                layman_advice=known["advice"],
                technical_notes=(
                    f"{known['tech']} | Endpoint: {remote_ip}:{remote_port_str} ({dest_org}) | "
                    f"Porta: {port_desc}."
                ),
                is_system_critical=is_crit,
            )

        return SecurityAnalysis(
            risk_level="SAFE",
            risk_badge="🟢 Seguro",
            destination_org=dest_org,
            layman_title=known["title"],
            layman_explanation=f"{known['layman']}\n• Conversando com: {dest_org} ({port_desc}).",
            layman_advice=known["advice"],
            technical_notes=(
                f"{known['tech']} | Endpoint: {remote_ip}:{remote_port_str} ({dest_org}) | "
                f"Porta: {port_desc}."
            ),
            is_system_critical=is_crit,
        )

    # ---------------- 5. DETECÇÃO HEURÍSTICA DE TELEMETRIA POR NOME/CAMINHO ----------------
    if any(kw in proc_lower or kw in path_lower for kw in TELEMETRY_KEYWORDS):
        return SecurityAnalysis(
            risk_level="TELEMETRY",
            risk_badge="🟡 Telemetria / Dados",
            destination_org=dest_org,
            layman_title=f"Coletor de Telemetria / Atualizador em Segundo Plano ({process_name})",
            layman_explanation=(
                f"Pelo nome e localização ('{process_name}'), este programa atua enviando diagnósticos, relatórios de erros "
                f"ou verificando atualizações silenciosamente para {dest_org}."
            ),
            layman_advice="✅ Seguro bloquear se você deseja impedir que este software envie dados de uso pela internet.",
            technical_notes=(
                f"[Heurística de Telemetria] Identificado padrão de telemetria/updater no binário '{exe_path}'. "
                f"Destino: {remote_ip}:{remote_port_str} ({dest_org})."
            ),
            is_system_critical=False,
        )

    # ---------------- 6. PROCESSOS DO SISTEMA WINDOWS EM SYSTEM32 ----------------
    if path_lower.startswith("c:\\windows\\system32") or path_lower.startswith("c:\\windows\\syswow64"):
        return SecurityAnalysis(
            risk_level="SAFE",
            risk_badge="🟢 Seguro (Sistema)",
            destination_org=dest_org,
            layman_title=f"Componente Oficial do Windows ({process_name})",
            layman_explanation=(
                f"Este executável faz parte do sistema operacional Windows (localizado na pasta protegida System32). "
                f"Destino: {dest_org} ({port_desc})."
            ),
            layman_advice="⚠️ Evite bloquear componentes da pasta System32 para não afetar funções de rede do Windows.",
            technical_notes=(
                f"Binário nativo do sistema em '{exe_path}'. Protocolo {proto}, Status {status}, Porta {port_desc}."
            ),
            is_system_critical=True,
        )

    # ---------------- 7. PROGRAMAS EM PASTAS PADRÃO (Program Files) ----------------
    if "program files" in path_lower:
        return SecurityAnalysis(
            risk_level="SAFE",
            risk_badge="🟢 Seguro",
            destination_org=dest_org,
            layman_title=f"Aplicativo Instalado ({process_name})",
            layman_explanation=(
                f"Programa instalado oficialmente na pasta 'Arquivos de Programas'. "
                f"Está se comunicando com {dest_org} usando {port_desc}."
            ),
            layman_advice="✅ Se você não quer que este programa acesse a internet, você pode bloqueá-lo no Firewall sem afetar o Windows.",
            technical_notes=(
                f"Aplicação padrão em '{exe_path}'. Fluxo {proto} {local_ip}:{local_port} -> {remote_ip}:{remote_port_str} ({dest_org})."
            ),
            is_system_critical=False,
        )

    # ---------------- 8. DEMAIS APLICATIVOS (Ex: AppData ou Pastas Customizadas) ----------------
    return SecurityAnalysis(
        risk_level="TELEMETRY",
        risk_badge="🟡 Atenção / App",
        destination_org=dest_org,
        layman_title=f"Programa de Usuário / Segundo Plano ({process_name})",
        layman_explanation=(
            f"Este programa está rodando fora da pasta padrão de Arquivos de Programas ('{exe_path}') "
            f"e está conectado a {dest_org} ({port_desc})."
        ),
        layman_advice="💡 Verifique se você conhece este aplicativo. Se não quiser que ele envie ou receba dados, clique em 'Bloquear no Firewall'.",
        technical_notes=(
            f"Executável em diretório de usuário/customizado: '{exe_path}'. "
            f"Endpoint: {proto} {local_ip}:{local_port} -> {remote_ip}:{remote_port_str} ({dest_org})."
        ),
        is_system_critical=False,
    )


def compute_file_sha256(file_path: str) -> str:
    """Calcula o hash SHA-256 do executável para auditoria técnica / VirusTotal."""
    if not file_path or not os.path.exists(file_path):
        return "Arquivo inacessível para cálculo de hash"
    try:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        return f"Erro ao calcular SHA-256: {e}"

