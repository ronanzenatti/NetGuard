"""
NetGuard - Gerenciador Inteligente de Regras do Windows Defender Firewall
Permite bloquear programas (.exe) ou endereços IP específicos com 1 clique,
possui travas de segurança contra bloqueio acidental de processos vitais do Windows
e permite listar/desbloquear qualquer regra criada pelo NetGuard.
"""

from __future__ import annotations

import datetime
import ipaddress
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


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
    target_value: str     # Caminho completo ou IP
    direction: str        # "Saída (Bloqueado)" / "Entrada"
    enabled: str          # "Ativo" / "Inativo"
    created_at: str = ""  # Timestamp de registro


def _get_storage_path() -> str:
    """Retorna o caminho seguro do arquivo JSON de persistência de bloqueios em AppData."""
    base_dir = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") or os.path.expanduser("~")
    netguard_dir = os.path.join(base_dir, "NetGuard")
    try:
        os.makedirs(netguard_dir, exist_ok=True)
    except Exception:
        pass
    return os.path.join(netguard_dir, "blocked_rules.json")


def _load_persistent_rules() -> Dict[str, dict]:
    """Carrega as regras persistidas do disco."""
    path = _get_storage_path()
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                return data
            if isinstance(data, list):
                return {item.get("rule_name"): item for item in data if isinstance(item, dict) and item.get("rule_name")}
    except Exception:
        pass
    return {}


def _save_persistent_rules(rules: Dict[str, dict]) -> None:
    """Salva o dicionário de regras persistidas no disco com integridade."""
    try:
        path = _get_storage_path()
        tmp_path = path + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(rules, f, ensure_ascii=False, indent=2)
        if os.path.exists(path):
            os.replace(tmp_path, path)
        else:
            os.rename(tmp_path, path)
    except Exception:
        pass


def _save_single_persistent_rule(
    rule_name: str,
    target_type: str,
    target_value: str,
    process_name: str = "",
    direction: str = "Saída (Bloqueado)",
    enabled: str = "Ativo",
) -> None:
    """Registra uma nova regra no banco persistente local."""
    rules = _load_persistent_rules()
    rules[rule_name] = {
        "rule_name": rule_name,
        "target_type": target_type,
        "target_value": target_value,
        "process_name": process_name,
        "direction": direction,
        "enabled": enabled,
        "created_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    _save_persistent_rules(rules)


def _remove_persistent_rule(rule_name: str) -> None:
    """Remove uma regra do banco persistente local."""
    rules = _load_persistent_rules()
    if rule_name in rules:
        del rules[rule_name]
        _save_persistent_rules(rules)


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
    """Cria uma regra de saída (Outbound) no Windows Firewall bloqueando o .exe e salva no registro permanente."""
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
        # Salva imediatamente no banco persistente em disco
        _save_single_persistent_rule(
            rule_name=rule_name,
            target_type="📦 Programa (.exe)",
            target_value=norm_path,
            process_name=process_name,
            direction="Saída (Bloqueado)",
            enabled="Ativo",
        )
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
    """Cria uma regra no Windows Firewall bloqueando toda comunicação com um IP remoto específico e persiste localmente."""
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
        # Salva imediatamente no banco persistente em disco
        _save_single_persistent_rule(
            rule_name=rule_name,
            target_type="🎯 Endereço IP",
            target_value=remote_ip,
            process_name=process_name,
            direction="Saída (Bloqueado)",
            enabled="Ativo",
        )
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


def _list_rules_via_netsh() -> List[dict]:
    """Lista regras do Windows Firewall via netsh advfirewall (método nativo rápido e independente de WMI/Cim)."""
    code, output = _run_netsh(["advfirewall", "firewall", "show", "rule", "name=all", "verbose"])
    if code != 0 or not output:
        return []

    rules: List[dict] = []
    blocks = re.split(r"\n(?=(?:Nome da Regra|Rule Name):)", output)
    for b in blocks:
        if RULE_PREFIX not in b:
            continue
        name_m = re.search(r"(?:Nome da Regra|Rule Name):\s*([^\r\n]+)", b)
        if not name_m:
            continue
        rname = name_m.group(1).strip()
        if not rname.startswith(RULE_PREFIX):
            continue

        prog_m = re.search(r"(?:Programa|Program):\s*([^\r\n]+)", b)
        ip_m = re.search(r"(?:RemoteIP):\s*([^\r\n]+)", b)
        enabled_m = re.search(r"(?:Habilitado|Enabled):\s*([^\r\n]+)", b)
        dir_m = re.search(r"(?:Dire[^\r\n:]*|Direction):\s*([^\r\n]+)", b)

        prog_val = prog_m.group(1).strip() if prog_m else ""
        if prog_val.lower() in ("qualquer", "any"):
            prog_val = ""

        ip_val = ip_m.group(1).strip() if ip_m else ""
        if ip_val.lower() in ("qualquer", "any"):
            ip_val = ""

        enabled_raw = enabled_m.group(1).strip().lower() if enabled_m else "sim"
        enabled = "Ativo" if enabled_raw in ("sim", "yes", "true", "1") else "Inativo"

        dir_raw = dir_m.group(1).strip().lower() if dir_m else "saida"
        direction = "Saída (Bloqueado)" if ("sa" in dir_raw or "out" in dir_raw) else "Entrada (Bloqueado)"

        rules.append({
            "rule_name": rname,
            "program": prog_val,
            "remote_ip": ip_val,
            "enabled": enabled,
            "direction": direction,
        })

    return rules


def _list_rules_via_powershell() -> List[dict]:
    """Lista regras do Windows Firewall via PowerShell Get-NetFirewallRule."""
    creation_flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
    ps_cmd = (
        "Get-NetFirewallRule -DisplayName 'NetGuard_Block_*' -ErrorAction SilentlyContinue | "
        "Select-Object DisplayName, Enabled, Direction | ConvertTo-Json -Compress"
    )
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            creationflags=creation_flags,
            timeout=12,
        )
        raw = (proc.stdout or "").strip()
        if not raw:
            return []

        data = json.loads(raw)
        if isinstance(data, dict):
            data = [data]

        rules: List[dict] = []
        for entry in data:
            name = str(entry.get("DisplayName", "")).strip()
            if not name or not name.startswith(RULE_PREFIX):
                continue
            enabled_raw = str(entry.get("Enabled", "True")).lower()
            enabled = "Ativo" if enabled_raw in ("true", "1", "sim", "yes") else "Inativo"
            rules.append({
                "rule_name": name,
                "program": "",
                "remote_ip": "",
                "enabled": enabled,
                "direction": "Saída (Bloqueado)",
            })
        return rules
    except Exception:
        return []


def list_netguard_rules() -> List[FirewallRuleItem]:
    """
    Lista todas as regras de bloqueio criadas pelo NetGuard.
    Garante persistência total e integridade:
    1. Carrega o banco de dados persistente local (AppData/NetGuard/blocked_rules.json).
    2. Sincroniza com as regras ativas do Firewall do Windows (via netsh nativo ou PowerShell).
    3. Importa regras do Firewall que ainda não estavam no JSON (ex: criadas antes ou por outra instância).
    4. Mesmo que o aplicativo seja fechado e reaberto em modo Usuário Padrão (não-admin),
       as regras permanecem salvas e visíveis no Gerenciador de Bloqueios.
    """
    persisted = _load_persistent_rules()

    # Tenta obter dados reais do Windows Defender Firewall
    fw_rules = _list_rules_via_netsh()
    if not fw_rules:
        fw_rules = _list_rules_via_powershell()

    # Sincroniza regras do Firewall no banco local persistente
    for r in fw_rules:
        rname = r["rule_name"]
        prog = r.get("program", "")
        rip = r.get("remote_ip", "")
        enabled = r.get("enabled", "Ativo")
        direction = r.get("direction", "Saída (Bloqueado)")

        if rname in persisted:
            persisted[rname]["enabled"] = enabled
            persisted[rname]["direction"] = direction
            if prog and not persisted[rname].get("target_value"):
                persisted[rname]["target_value"] = prog
        else:
            # Regra ativa no Firewall que não constava no arquivo local
            if "_App_" in rname:
                ttype = "📦 Programa (.exe)"
                tval = prog or rname.replace(f"{RULE_PREFIX}App_", "")
                pname = os.path.basename(tval)
            elif "_IP_" in rname:
                ttype = "🎯 Endereço IP"
                tval = rip or rname.replace(f"{RULE_PREFIX}IP_", "")
                pname = ""
            else:
                ttype = "🛡️ Regra Customizada"
                tval = rname
                pname = ""

            persisted[rname] = {
                "rule_name": rname,
                "target_type": ttype,
                "target_value": tval,
                "process_name": pname,
                "direction": direction,
                "enabled": enabled,
                "created_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }

    # Se obtivemos retorno ativo do Firewall, salva o estado atualizado
    if fw_rules:
        _save_persistent_rules(persisted)

    items: List[FirewallRuleItem] = []
    for rname, data in persisted.items():
        items.append(
            FirewallRuleItem(
                rule_name=rname,
                target_type=data.get("target_type", "🛡️ Regra Customizada"),
                target_value=data.get("target_value", rname),
                direction=data.get("direction", "Saída (Bloqueado)"),
                enabled=data.get("enabled", "Ativo"),
                created_at=data.get("created_at", ""),
            )
        )

    # Ordenar por nome da regra
    items.sort(key=lambda x: x.rule_name)
    return items


def remove_netguard_rule(rule_name: str) -> Tuple[bool, str]:
    """
    Remove (desbloqueia) uma regra criada pelo NetGuard no Windows Firewall e no banco persistente.
    """
    if not rule_name.startswith(RULE_PREFIX):
        return False, "Apenas regras criadas pelo NetGuard podem ser removidas por aqui."

    # Tenta remover do Windows Defender Firewall via netsh
    code, msg = _run_netsh(["advfirewall", "firewall", "delete", "rule", f"name={rule_name}"])

    msg_lower = msg.lower()
    is_not_found = "nenhuma regra" in msg_lower or "no rules match" in msg_lower

    if code == 0 or is_not_found:
        _remove_persistent_rule(rule_name)
        return True, f"🔓 Bloqueio '{rule_name}' removido com sucesso! O acesso foi restaurado."

    if "administrador" in msg_lower or "administrator" in msg_lower or "privil" in msg_lower:
        return (
            False,
            "Permissão negada pelo Windows Defender Firewall. É necessário executar o NetGuard como Administrador para remover regras do sistema.",
        )

    return False, f"Erro ao remover regra '{rule_name}': {msg}"


