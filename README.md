# 🛡️ NetGuard 2.0 — Cibersegurança, Privacidade & Monitor de Conexões Ativas

> **👨‍💻 Desenvolvido por Ronan Adriel Zenatti**  
> **✉️ Contato:** [ronanzenatti@gmail.com](mailto:ronanzenatti@gmail.com)

Uma aplicação desktop moderna desenvolvida em Python que une **dois mundos**:
1. **Para Usuários Leigos**: Semáforo de Risco (**🟢 Seguro**, **🟡 Telemetria/Dados**, **🔴 Suspeito**), identificação automática da empresa/país do outro lado da conexão, explicação em português claro sobre cada programa, janelas de decisão coloridas em negrito e bloqueio/desbloqueio no Firewall do Windows com 1 clique.
2. **Para Estudantes e Entusiastas de Cibersegurança**: Todos os dados brutos de sockets (IPv4/IPv6, TCP/UDP, PID, portas locais/remotas, estados `LISTEN`/`ESTABLISHED`/`TIME_WAIT`), DNS Reverso (`PTR`), heurísticas baseadas em **MITRE ATT&CK (T1036 Masquerading)**, detecção de portas de C2/RAT/Mineração e cálculo instantâneo de hash **SHA-256** para auditoria no VirusTotal.

---

## ✨ Recursos Principais do NetGuard 2.0

### 🚦 1. Motor Heurístico de Cibersegurança (`security_engine.py`)
- **Detecção de Impostores de Sistema (*Process Masquerading - MITRE T1036*)**: Verifica se processos críticos como `svchost.exe`, `lsass.exe`, `csrss.exe` ou `explorer.exe` estão executando fora de `C:\Windows\System32`.
- **Detecção de Execução em Pastas Voláteis**: Alerta vermelho se um binário abrir conexões externas a partir de pastas temporárias (`AppData\Local\Temp`, `Downloads`, `$Recycle.Bin`).
- **Radar de Portas de Invasão e Mineração**: Identifica conexões em portas conhecidas de *Backdoors*, *Meterpreter* (`4444`), *IRC Botnets* (`6667`/`6697`) e *CryptoMiners* (`3333`, `14444`).
- **Detector de Telemetria e Coleta de Dados**: Destaca em amarelo (`🟡 Telemetria / Dados`) processos que enviam diagnósticos ou métricas em segundo plano (ex.: `nvcontainer.exe`, `CompatTelRunner.exe`, atualizadores silenciosos).

### 🌍 2. Identificação de Destino, Empresa e País (IP Intelligence)
- Traduz endereços IP brutos em nomes compreensíveis:
  - **Grandes Provedores**: `🇺🇸 Google LLC`, `🇺🇸 Microsoft Corporation (Azure)`, `🇺🇸 GitHub / Fastly`, `🇺🇸 Meta Platforms (WhatsApp/Facebook)`, `🇺🇸 Cloudflare`, `🌐 Akamai CDN`.
  - **Dispositivos na Sua Casa (LAN)**: Identifica `🏠 Seu Roteador / Gateway Wi-Fi`, `🏠 Rede Local (Smart TV / Chromecast)` (porta 8009), `📡 Multicast / Descoberta UPnP`.
  - **GeoIP & DNS Reverso Assíncrono**: Resolve em segundo plano o país (com bandeira), provedor (ASN/ISP) e registro `PTR` de IPs públicos desconhecidos sem travar a interface.

### 🔬 3. Painel Inspetor Duplo (Leigo + Cybersec)
Ao clicar em qualquer conexão na tabela, o painel inferior exibe lado a lado:
- **Visão para Leigos**: O que é o programa, com quem está falando e uma recomendação clara (*"✅ Seguro bloquear se não quiser telemetria"* vs *"⛔ Não bloqueie: componente vital do Windows"*).
- **Visão Técnica / Forense**: Dados brutos do socket, hostname reverso (`rDNS`), notas técnicas e botão **`🔑 Hash SHA-256`** que calcula e copia o hash do executável para a Área de Transferência.

### 🧱 4. Integração com o Windows Defender Firewall (`firewall_manager.py`)
- **🚫 Bloquear Programa (`.exe`)**: Cria uma regra de saída no Windows Firewall impedindo que o executável acesse a internet.
- **🎯 Bloquear Apenas Este IP**: Corta a comunicação do computador apenas com aquele servidor específico (ótimo para bloquear um servidor de telemetria sem impedir o programa de funcionar na rede local).
- **🛡️ Trava Anti-Acidente**: Impede que um usuário leigo bloqueie por engano o Kernel do Windows (`ntoskrnl.exe`), `svchost.exe` legítimo, o Windows Defender ou o próprio roteador Wi-Fi (`192.168.1.1`).
- **🔓 Central de Bloqueios (Desfazer com 1 Clique)**: O botão **`🧱 Gerenciar Bloqueios (Firewall)`** no topo da janela lista todas as regras criadas pelo NetGuard e permite restaurar o acesso instantaneamente.

---

## 🤖 Build e Publicação Automática no GitHub (CI/CD)

Este repositório conta com um pipeline automatizado do **GitHub Actions** ([`.github/workflows/build-exe.yml`](file:///c:/Users/USUARIO/Desktop/port/.github/workflows/build-exe.yml)).

A cada **`git push`**:
1. O GitHub provisiona uma máquina virtual Windows limpa (`windows-latest`).
2. Instala o Python 3.12 e as versões mais recentes de todas as dependências.
3. Compila o executável autônomo **`NetGuard.exe`** via PyInstaller e calcula seu hash **`NetGuard.exe.sha256`**.
4. Disponibiliza o executável para download imediato em **dois lugares**:
   - Na aba **Releases** do repositório no GitHub (tag `latest`, sempre atualizada com o último push).
   - Na aba **Actions** (como *Artifact* `NetGuard-Windows-Executable`).

---

## 🚀 Como Executar Localmente

### Opção 1: Executável Autônomo (`.exe`)
- Baixe na aba **Releases** do GitHub ou execute em `dist\NetGuard.exe`.

### Opção 2: Script Rápido (`run.bat`)
- Dê um duplo clique em [`run.bat`](file:///c:/Users/USUARIO/Desktop/port/run.bat).

### Opção 3: Via Terminal (`.venv`)
```powershell
python -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt
.\.venv\Scripts\python.exe main.py
```

---

## 👨‍💻 Autor

- **Ronan Adriel Zenatti**
- **E-mail:** [ronanzenatti@gmail.com](mailto:ronanzenatti@gmail.com)
