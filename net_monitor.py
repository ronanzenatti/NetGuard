"""
NetGuard - Módulo de Monitoramento de Conexões, Processos e Análise de Cibersegurança
Responsável pela coleta de conexões ativas, resolução de executáveis,
integração com o motor de segurança, gerenciamento de privilégios UAC e controle de processos.
"""

from __future__ import annotations

import ctypes
import os
import socket
import subprocess
import sys
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import psutil

from security_engine import SecurityAnalysis, evaluate_connection_security


@dataclass
class ConnectionItem:
    """Representa uma conexão de rede ativa, o processo associado e a análise de cibersegurança."""
    pid: Optional[int]
    process_name: str
    proto: str
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: str
    status: str
    exe_path: str
    username: str
    security: SecurityAnalysis

    def to_dict(self) -> dict:
        return {
            "risk_badge": self.security.risk_badge,
            "pid": self.pid or "-",
            "process_name": self.process_name,
            "proto": self.proto,
            "local_ip": self.local_ip,
            "local_port": self.local_port,
            "remote_ip": self.remote_ip,
            "remote_port": self.remote_port,
            "destination_org": self.security.destination_org,
            "status": self.status,
            "username": self.username,
            "exe_path": self.exe_path,
        }


def is_admin() -> bool:
    """Verifica se o processo atual possui privilégios de Administrador no Windows."""
    if sys.platform != "win32":
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def request_admin_elevation(target_script: Optional[str] = None) -> bool:
    """
    Solicita elevação de UAC no Windows para executar com privilégios de Administrador.
    Retorna True se o processo elevado foi disparado com sucesso.
    Compatível com script Python direto e executável compilado (.exe).
    """
    if sys.platform != "win32":
        return False

    is_frozen = getattr(sys, "frozen", False)
    if is_frozen:
        exe = os.path.abspath(sys.executable)
        parameters = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
    else:
        script = os.path.abspath(target_script or sys.argv[0])
        exe = os.path.abspath(sys.executable)
        args = [f'"{script}"'] + [f'"{arg}"' for arg in sys.argv[1:]]
        parameters = " ".join(args)

    try:
        ret = ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            exe,
            parameters,
            None,
            1  # SW_SHOWNORMAL
        )
        if int(ret) > 32:
            return True
    except Exception as e:
        print(f"Erro ao solicitar elevação: {e}")

    return False


class ProcessCache:
    """Cache inteligente de informações de processos para alta performance nas atualizações."""
    def __init__(self):
        self._cache: Dict[int, Tuple[float, str, str, str]] = {}

    def get_info(self, pid: Optional[int]) -> Tuple[str, str, str]:
        """
        Retorna (nome_processo, caminho_executavel, usuario).
        Utiliza cache validando o tempo de criação do PID para evitar dados de processos reciclados.
        """
        if not pid or pid == 0:
            return ("Sistema / Kernel", "C:\\Windows\\System32\\ntoskrnl.exe", "SYSTEM")

        try:
            proc = psutil.Process(pid)
            create_time = proc.create_time()

            if pid in self._cache:
                cached_time, name, exe, user = self._cache[pid]
                if cached_time == create_time:
                    return name, exe, user

            try:
                name = proc.name() or "Desconhecido"
            except Exception:
                name = f"PID {pid}"

            try:
                exe = proc.exe() or "Não disponível"
            except psutil.AccessDenied:
                exe = "Acesso Negado (Requer Elevação)"
            except Exception:
                exe = "Não disponível"

            try:
                user = proc.username() or "-"
            except Exception:
                user = "-"

            self._cache[pid] = (create_time, name, exe, user)
            return name, exe, user

        except psutil.NoSuchProcess:
            self._cache.pop(pid, None)
            return ("Finalizado", "Processo encerrado", "-")
        except psutil.AccessDenied:
            return ("Restrito", "Acesso Negado (Requer Elevação)", "SYSTEM / Outro")
        except Exception:
            return ("Indisponível", "Erro ao obter dados", "-")

    def clean_dead_processes(self, active_pids: set[int]):
        """Remove entradas obsoletas do cache."""
        cached_pids = list(self._cache.keys())
        for pid in cached_pids:
            if pid not in active_pids:
                self._cache.pop(pid, None)


_process_cache = ProcessCache()


def get_active_connections() -> List[ConnectionItem]:
    """
    Coleta todas as conexões de rede ativas (IPv4 e IPv6, TCP e UDP),
    vincula cada conexão ao executável responsável e executa a avaliação de cibersegurança.
    """
    connections: List[ConnectionItem] = []
    active_pids: set[int] = set()

    try:
        raw_conns = psutil.net_connections(kind="inet")
    except Exception as e:
        print(f"Erro ao obter conexões de rede: {e}")
        return []

    for conn in raw_conns:
        pid = conn.pid
        if pid:
            active_pids.add(pid)

        name, exe, user = _process_cache.get_info(pid)

        proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"

        local_ip = conn.laddr.ip if conn.laddr else "-"
        local_port = conn.laddr.port if conn.laddr else 0

        remote_ip = conn.raddr.ip if conn.raddr else "-"
        remote_port = str(conn.raddr.port) if conn.raddr else "-"

        status = conn.status if conn.status else ("UDP_LISTENING" if proto == "UDP" and not conn.raddr else "NONE")

        sec_analysis = evaluate_connection_security(
            pid=pid,
            process_name=name,
            exe_path=exe,
            proto=proto,
            local_ip=local_ip,
            local_port=local_port,
            remote_ip=remote_ip,
            remote_port_str=remote_port,
            status=status,
        )

        item = ConnectionItem(
            pid=pid,
            process_name=name,
            proto=proto,
            local_ip=local_ip,
            local_port=local_port,
            remote_ip=remote_ip,
            remote_port=remote_port,
            status=status,
            exe_path=exe,
            username=user,
            security=sec_analysis,
        )
        connections.append(item)

    _process_cache.clean_dead_processes(active_pids)
    return connections


def terminate_process(pid: int) -> Tuple[bool, str]:
    """Tenta finalizar o processo especificado pelo PID."""
    if not pid or pid == 0:
        return False, "Não é possível finalizar processos do kernel do sistema."

    try:
        proc = psutil.Process(pid)
        proc_name = proc.name()
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except psutil.TimeoutExpired:
            proc.kill()
        return True, f"Processo '{proc_name}' (PID {pid}) encerrado com sucesso."
    except psutil.NoSuchProcess:
        return False, f"O processo PID {pid} já não se encontra em execução."
    except psutil.AccessDenied:
        return False, f"Acesso negado ao tentar encerrar o PID {pid}. Execute como Administrador."
    except Exception as e:
        return False, f"Erro inesperado ao finalizar PID {pid}: {e}"


def open_file_in_explorer(file_path: str) -> Tuple[bool, str]:
    """
    Abre o Windows Explorer com o executável selecionado e focado.
    Corrige o comportamento nativo do Explorer no Windows onde parâmetros com espaços
    dentro do switch /select abriam a pasta 'Documentos' por engano.
    """
    if not file_path:
        return False, "Nenhum caminho de arquivo foi informado para este processo."

    clean_path = str(file_path).strip().strip('"').strip("'")

    if clean_path in ("Não disponível", "Processo encerrado", "Erro ao obter dados") or "Acesso Negado" in clean_path:
        return (
            False,
            f"O caminho deste processo não está acessível no disco ({clean_path}).\n"
            "Se for um serviço do sistema, execute o NetGuard como Administrador.",
        )

    norm = os.path.normpath(clean_path)

    # 1. Se o arquivo existe no disco
    if os.path.exists(norm):
        try:
            if os.path.isfile(norm):
                # No Windows, apenas o caminho deve estar entre aspas, NUNCA o switch /select,
                cmd = f'explorer.exe /select,"{norm}"'
            else:
                cmd = f'explorer.exe "{norm}"'

            subprocess.Popen(cmd, shell=False)
            return True, f"Pasta aberta com sucesso e arquivo destacado:\n{norm}"
        except Exception as e:
            return False, f"Falha ao executar o Windows Explorer: {e}"

    # 2. Se o arquivo específico não for encontrado, tentar abrir a pasta pai
    parent_dir = os.path.dirname(norm)
    if parent_dir and os.path.isdir(parent_dir):
        try:
            subprocess.Popen(f'explorer.exe "{parent_dir}"', shell=False)
            return True, f"O executável não foi encontrado diretamente, mas a pasta foi aberta:\n{parent_dir}"
        except Exception as e:
            return False, f"Falha ao abrir a pasta pai no Explorer: {e}"

    return False, f"Caminho não encontrado ou inacessível no disco:\n{norm}"
