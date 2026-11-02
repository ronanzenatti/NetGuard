# 🛡️ NetGuard 2.0 — Cibersegurança, Privacidade & Monitor de Conexões Ativas

[![Build & Publish NetGuard (.exe)](https://github.com/ronanzenatti/NetGuard/actions/workflows/build-exe.yml/badge.svg)](https://github.com/ronanzenatti/NetGuard/actions/workflows/build-exe.yml)
[![Download NetGuard.exe](https://img.shields.io/badge/Download-NetGuard.exe-brightgreen?logo=windows&logoColor=white)](https://github.com/ronanzenatti/NetGuard/releases/latest/download/NetGuard.exe)
[![Releases](https://img.shields.io/github/v/release/ronanzenatti/NetGuard?color=blue&label=Vers%C3%A3o)](https://github.com/ronanzenatti/NetGuard/releases/latest)
[![License](https://img.shields.io/badge/Licen%C3%A7a-MIT-blue.svg)](LICENSE)

> **👨‍💻 Desenvolvido por Ronan Adriel Zenatti**  
> **✉️ Contato:** [ronanzenatti@gmail.com](mailto:ronanzenatti@gmail.com)  
> **🔗 Repositório Oficial:** [github.com/ronanzenatti/NetGuard](https://github.com/ronanzenatti/NetGuard)

---

### 📥 Download Imediato do Executável

Não precisa instalar Python nem configurar nada! Basta baixar o executável pronto para Windows:

👉 **[Clique aqui para baixar o NetGuard.exe (Versão Mais Recente)](https://github.com/ronanzenatti/NetGuard/releases/latest/download/NetGuard.exe)**

---

## 🎯 Sobre o NetGuard 2.0

O **NetGuard 2.0** é uma aplicação desktop desenvolvida em Python que une **dois mundos**:
1. **Para Usuários Leigos**: Semáforo de Risco (**🟢 Seguro**, **🟡 Telemetria/Atenção**, **🔴 Suspeito**), identificação automática da empresa/país do outro lado da conexão (Google, Microsoft, Meta, Smart TV local), tradutor em português claro explicando o que cada programa faz e **bloqueio/desbloqueio no Windows Firewall com 1 clique**.
2. **Para Estudantes e Entusiastas de Cibersegurança**: Todos os dados brutos de sockets (IPv4/IPv6, TCP/UDP, PID, portas locais/remotas, estados `LISTEN`/`ESTABLISHED`/`TIME_WAIT`), DNS Reverso (`rDNS / PTR`), heurísticas baseadas em **MITRE ATT&CK (T1036 Masquerading)**, detecção de portas de C2/RAT/Mineração e cálculo instantâneo de hash **SHA-256** para auditoria no VirusTotal.

---

## ✨ Recursos Principais

### 🚦 1. Motor Heurístico de Cibersegurança (`security_engine.py`)
- **Detecção de Impostores de Sistema (*Process Masquerading - MITRE T1036*)**: Detecta se processos críticos como `svchost.exe`, `lsass.exe`, `csrss.exe` ou `explorer.exe` estão executando fora de `C:\Windows\System32`.
- **Detecção de Execução em Pastas Voláteis**: Alerta vermelho caso um executável abra conexões externas a partir de pastas temporárias (`AppData\Local\Temp`, `Downloads`, `$Recycle.Bin`).
- **Radar de Portas de Invasão e Mineração**: Identifica conexões em portas comumente associadas a *Backdoors*, *Meterpreter* (`4444`), *IRC Botnets* (`6667`/`6697`) e *CryptoMiners* (`3333`, `14444`).
- **Detector de Telemetria e Coleta de Dados**: Destaca em amarelo (`🟡 Telemetria / Atenção`) processos que enviam diagnósticos ou métricas em segundo plano (ex.: `nvcontainer.exe`, `CompatTelRunner.exe`, atualizadores silenciosos).

### 🌍 2. Identificação de Destino, Empresa e País (IP Intelligence)
- Traduz endereços IP brutos em nomes legíveis e intuitivos:
  - **Grandes Provedores Globais**: `🇺🇸 Google LLC`, `🇺🇸 Microsoft Corporation (Azure)`, `🇺🇸 GitHub / Fastly`, `🇺🇸 Meta Platforms (WhatsApp/Facebook)`, `🇺🇸 Cloudflare`, `🌐 Akamai CDN`.
  - **Dispositivos na Sua Casa (LAN)**: Identifica `🏠 Seu Roteador / Gateway Wi-Fi`, `🏠 Rede Local (Smart TV / Chromecast)` (porta 8009), `📡 Multicast / Descoberta UPnP`.
  - **GeoIP & DNS Reverso Assíncrono**: Resolve em segundo plano o país (com bandeira), provedor (ASN/ISP) e registro `PTR` de IPs públicos desconhecidos sem travar a interface.

### 🔬 3. Painel Inspetor Duplo (Leigo + Cybersec)
Ao selecionar qualquer conexão na tabela, o painel inferior exibe lado a lado:
- **Visão para Leigos**: Explica o que é o programa, com quem está falando e uma recomendação clara (*"✅ Seguro bloquear se não quiser telemetria"* vs *"⛔ Não bloqueie: componente vital do Windows"*).
- **Visão Técnica / Forense**: Dados brutos do socket, hostname reverso (`rDNS`), notas técnicas e o botão **`🔑 Hash SHA-256`** que calcula e copia a impressão digital criptográfica do executável para auditoria no VirusTotal.

### 🧱 4. Integração com o Windows Defender Firewall (`firewall_manager.py`)
- **🚫 Bloquear Programa (`.exe`)**: Cria regra de saída no Windows Firewall impedindo que o executável selecionado acerte conexões com a internet.
- **🎯 Bloquear Apenas Este IP**: Corta a comunicação do computador apenas com aquele servidor específico (ideal para bloquear telemetria sem impedir o aplicativo de funcionar).
- **🛡️ Trava Anti-Acidente**: Impede que um usuário leigo bloqueie por engano o Kernel do Windows (`ntoskrnl.exe`), `svchost.exe` legítimo, o Windows Defender ou o próprio roteador Wi-Fi (`192.168.1.1`).
- **🔓 Central de Bloqueios (Desfazer com 1 Clique)**: O botão **`🧱 Gerenciar Bloqueios (Firewall)`** no topo da janela lista todas as regras criadas e permite restaurar o acesso instantaneamente.

### 🧹 5. Modo Simplificado vs. Dados Brutos
- Interruptor **`Ocultar Ruído (TIME_WAIT/Local)`**: Esconde conexões já encerradas e loopbacks internos (`127.0.0.1`), deixando apenas o tráfego externo real. Desative para visualizar 100% dos sockets brutos.

---

## 🤖 Build e Publicação Automática (GitHub Actions CI/CD)

O repositório possui integração contínua configurada em [`.github/workflows/build-exe.yml`](.github/workflows/build-exe.yml).

A cada **`git push`**:
1. O GitHub inicia uma máquina virtual Windows limpa (`windows-latest`).
2. Instala o Python 3.12 e as dependências mais recentes de [`requirements.txt`](requirements.txt).
3. Compila o executável autônomo **`NetGuard.exe`** via PyInstaller e gera o arquivo de auditoria **`NetGuard.exe.sha256`**.
4. Atualiza automaticamente a [Release Oficial no GitHub](https://github.com/ronanzenatti/NetGuard/releases/latest) com os novos binários prontos para download.

---

## 🚀 Como Executar pelo Código Fonte

Caso queira executar em modo desenvolvedor:

```powershell
# 1. Clonar o repositório
git clone https://github.com/ronanzenatti/NetGuard.git
cd NetGuard

# 2. Criar e ativar o ambiente virtual
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 3. Instalar dependências
pip install -r requirements.txt

# 4. Executar o aplicativo
python main.py
```

Ou execute diretamente pelo script auxiliar [`run.bat`](run.bat).

---

## 👨‍💻 Autor e Suporte

- **Desenvolvedor:** Ronan Adriel Zenatti
- **E-mail:** [ronanzenatti@gmail.com](mailto:ronanzenatti@gmail.com)
- **GitHub:** [@ronanzenatti](https://github.com/ronanzenatti)
