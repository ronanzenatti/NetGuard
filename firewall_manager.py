"""
NetGuard - Gerenciador Inteligente de Regras do Windows Defender Firewall
Permite bloquear programas (.exe) ou endereços IP específicos com 1 clique,
possui travas de segurança contra bloqueio acidental de processos vitais do Windows
e permite listar/desbloquear qualquer regra criada pelo NetGuard.
"""

from __future__ import annotations

import ipaddress
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import List, Tuple


RULE_PREFIX = "NetGuard_Block_"

# Processos vitais do Windows que possuem trava contra bloqueio completo de executável
PROTECTED_EXECUTABLES = {
    "ntoskrnl.exe",
    "svchost.exe",
    "lsass.exe",
    "services.exe",
    "csrss.exe",
    "wininit.exe",
    "smss.exe",
    "explorer.exe",
    "mpdefendercoservice.exe",
    "msmpeng.exe",
    "dns.exe",
}


@dataclass
class FirewallRuleItem:
    rule_name: str
    target_type: str      # "Programa (.exe)" ou "Endereço IP"
    target_value: str     # Caminho ou IP
    direction: str        # "Saída (Outbound)" / "Entrada"
    enabled: str          # "Sim" / "Não"


def _run_netsh(args: List[str]) -> Tuple[int, str]:
    """Executa comando netsh ocultando janela de console."""
    creation_flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
    try:
        proc = subprocess.run(
            ["netsh"] + args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            creationflags=creation_flags,
            timeout=10,
        )
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        return proc.returncode, output.strip()
    except Exception as e:
        return 1, str(e)


def validate_executable_block(process_name: str, exe_path: str) -> Tuple[bool, str, bool]:
    """
    Verifica se é seguro bloquear o executável.
    Retorna (pode_bloquear, mensagem_explicativa, requer_confirmacao_extra).
    """
    proc_lower = (process_name or "").lower().strip()
    path_lower = (exe_path or "").lower().strip()

    if not exe_path or not os.path.exists(exe_path):
        return (
            False,
            f"O caminho do executável ('{exe_path}') não foi encontrado no disco ou pertence ao Kernel do sistema.",
            False,
        )

    # Se for processo protegido E estiver na pasta legítima do Windows -> Impedir bloqueio acidental do binário
    if proc_lower in PROTECTED_EXECUTABLES and (
        "c:\\windows\\system32" in path_lower or "windows defender" in path_lower
    ):
        return (
            False,
            f"🛡️ Trava de Segurança Ativada:\n\n"
            f"O processo '{process_name}' é um componente vital do Windows / Antivírus.\n"
            f"Bloquear o executável inteiro pode deixar seu computador sem internet ou sem proteção.\n\n"
            f"💡 Dica: Se você quiser bloquear apenas a conexão específica atual, use o botão '🎯 Bloquear Apenas Este IP Remoto'.",
            False,
        )

    if proc_lower in ("chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe"):
        return (
            True,
            f"Você está prestes a bloquear seu navegador de internet ({process_name}).\n"
            f"Se fizer isso, você não conseguirá abrir nenhum site nele até desbloqueá-lo na Central de Firewall do NetGuard.\n\n"
            f"Deseja realmente bloquear o navegador inteiro?",
            True,
        )

    return (
        True,
        f"Deseja bloquear o acesso à internet para o programa:\n\n"
        f"📦 Programa: {process_name}\n"
        f"📂 Caminho: {exe_path}\n\n"
        f"Você poderá desfazer esse bloqueio a qualquer momento com 1 clique no botão '🛡️ Gerenciar Bloqueios'.",
        False,
    )


def block_executable_in_firewall(process_name: str, exe_path: str) -> Tuple[bool, str]:
    """Cria uma regra de saída (Outbound) e entrada (Inbound) no Windows Firewall bloqueando o .exe."""
    norm_path = os.path.normpath(exe_path)
    safe_name = re.sub(r"[^a-zA-Z0-9_.-]", "_", process_name)
    rule_name = f"{RULE_PREFIX}App_{safe_name}"

    # Remover regra anterior com mesmo nome para evitar duplicatas
    _run_netsh(["advfirewall", "firewall", "delete", "rule", f"name={rule_name}"])

    # Criar regra de bloqueio de saída (Outbound)
    code_out, out_msg = _run_netsh([
        "advfirewall",
        "firewall",
        "add",
        "rule",
        f"name={rule_name}",
        "dir=out",
        "action=block",
        f"program={norm_path}",
        "enable=yes",
        "profile=any",
        f"description=Bloqueado pelo NetGuard: {norm_path}",
    ])

    if code_out == 0:
        return (
            True,
            f"✅ Programa '{process_name}' bloqueado com sucesso no Firewall do Windows!\n\n"
            f"Regra criada: {rule_name}\n"
            f"Para desbloquear no futuro, clique em '🛡️ Gerenciar Bloqueios'.",
        )
    return (
        False,
        f"Não foi possível criar a regra no Firewall.\nCertifique-se de que o NetGuard está rodando como Administrador.\n\nDetalhe: {out_msg}",
    )


def block_ip_in_firewall(remote_ip: str, process_name: str = "") -> Tuple[bool, str]:
    """Cria uma regra no Windows Firewall bloqueando toda comunicação com um IP remoto específico."""
    if not remote_ip or remote_ip in ("-", "0.0.0.0", "::", "*", "127.0.0.1", "::1"):
        return False, "Este endereço IP é local/interno do próprio computador e não deve ser bloqueado."

    try:
        ip_obj = ipaddress.ip_address(remote_ip)
        if ip_obj.is_loopback:
            return False, "Não é permitido bloquear o endereço de Loopback (127.0.0.1)."
        if ip_obj.is_private and remote_ip.endswith(".1"):
            return (
                False,
                f"🛡️ Trava de Segurança: O endereço {remote_ip} parece ser o seu Roteador Wi-Fi (Gateway).\n"
                "Bloqueá-lo cortaria toda a sua conexão com a internet!",
            )
    except ValueError:
        return False, f"Endereço IP inválido: {remote_ip}"

    safe_ip = remote_ip.replace(":", "_")
    context_tag = f"_{re.sub(r'[^a-zA-Z0-9]', '', process_name)[:12]}" if process_name else ""
    rule_name = f"{RULE_PREFIX}IP_{safe_ip}{context_tag}"

    # Evitar duplicatas
    _run_netsh(["advfirewall", "firewall", "delete", "rule", f"name={rule_name}"])

    code_out, out_msg = _run_netsh([
        "advfirewall",
        "firewall",
        "add",
        "rule",
        f"name={rule_name}",
        "dir=out",
        "action=block",
        f"remoteip={remote_ip}",
        "enable=yes",
        "profile=any",
        f"description=IP {remote_ip} bloqueado pelo NetGuard (Processo associado: {process_name})",
    ])

    if code_out == 0:
        return (
            True,
            f"✅ Endereço IP '{remote_ip}' bloqueado com sucesso no Firewall!\n\n"
            f"O seu computador não enviará mais dados para este servidor.\n"
            f"Regra criada: {rule_name}",
        )
    return (
        False,
        f"Falha ao bloquear o IP {remote_ip}. Verifique se está em Modo Administrador.\n\nDetalhe: {out_msg}",
    )


def list_netguard_rules() -> List[FirewallRuleItem]:
    """Lista todas as regras de bloqueio ativas criadas pelo NetGuard."""
    # Usamos PowerShell Get-NetFirewallRule para listagem estruturada e independente do idioma do Windows
    creation_flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
    ps_cmd = (
        "Get-NetFirewallRule -DisplayName 'NetGuard_Block_*' -ErrorAction SilentlyContinue | "
        "Select-Object DisplayName, Enabled, Direction | ConvertTo-Json -Compress"
    )
    rules: List[FirewallRuleItem] = []
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            creationflags=creation_flags,
            timeout=8,
        )
        raw = (proc.stdout or "").strip()
        if not raw:
            return []

        import json
        data = json.loads(raw)
        if isinstance(data, dict):
            data = [data]

        seen_names = set()
        for entry in data:
            name = str(entry.get("DisplayName", ""))
            if not name or name in seen_names:
                continue
            seen_names.add(name)

            if "_App_" in name:
                ttype = "📦 Programa (.exe)"
                tval = name.replace(f"{RULE_PREFIX}App_", "")
            elif "_IP_" in name:
                ttype = "🎯 Endereço IP"
                tval = name.replace(f"{RULE_PREFIX}IP_", "")
            else:
                ttype = "🛡️ Regra Customizada"
                tval = name

            enabled = "Ativo" if str(entry.get("Enabled", "True")).lower() in ("true", "1") else "Inativo"
            rules.append(
                FirewallRuleItem(
                    rule_name=name,
                    target_type=ttype,
                    target_value=tval,
                    direction="Saída (Bloqueado)",
                    enabled=enabled,
                )
            )
    except Exception:
        pass

    return rules


def remove_netguard_rule(rule_name: str) -> Tuple[bool, str]:
    """Remove (desbloqueia) uma regra criada pelo NetGuard no Windows Firewall."""
    if not rule_name.startswith(RULE_PREFIX):
        return False, "Apenas regras criadas pelo NetGuard podem ser removidas por aqui."

    code, msg = _run_netsh(["advfirewall", "firewall", "delete", "rule", f"name={rule_name}"])
    if code == 0:
        return True, f"🔓 Bloqueio '{rule_name}' removido com sucesso! O acesso foi restaurado."
    return False, f"Erro ao remover regra '{rule_name}': {msg}"

