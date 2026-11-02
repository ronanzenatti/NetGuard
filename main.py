"""
NetGuard 2.0 — Monitor de Cibersegurança, Privacidade, Conexões e Firewall
Une o melhor de dois mundos:
- Para Leigos: Tradutor em português claro, Semáforo de Risco, Identificação de Empresas/Países,
  Janelas de Decisão Coloridas em Negrito e Bloqueio de Firewall com 1 clique.
- Para Estudantes/Entusiastas de Cibersegurança: Todos os dados brutos de sockets, PIDs, portas,
  estados TCP/UDP, rDNS, notas MITRE ATT&CK e cálculo de Hash SHA-256.
"""

from __future__ import annotations

import csv
import ctypes
import datetime
import os
import sys
import threading
from tkinter import filedialog, ttk
from typing import Dict, List, Optional

import customtkinter as ctk

from firewall_manager import (
    FirewallRuleItem,
    block_executable_in_firewall,
    block_ip_in_firewall,
    list_netguard_rules,
    remove_netguard_rule,
    validate_executable_block,
)
from net_monitor import (
    ConnectionItem,
    get_active_connections,
    is_admin,
    open_file_in_explorer,
    request_admin_elevation,
    terminate_process,
)
from security_engine import compute_file_sha256, ip_intel
from ui_dialogs import (
    ModernContextMenu,
    ask_modern_confirmation,
    show_modern_status,
)

# Habilitar DPI Awareness para nitidez em telas FullHD/4K no Windows
try:
    if sys.platform == "win32":
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
except Exception:
    pass

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")


class FirewallManagerWindow(ctk.CTkToplevel):
    """Janela dedicada para gerenciar e desbloquear programas/IPs bloqueados pelo NetGuard."""

    def __init__(self, parent: "NetGuardApp"):
        super().__init__(parent)
        self.parent_app = parent
        self.title("🛡️ Central de Bloqueios do Firewall — NetGuard")
        self.geometry("900x520")
        self.minsize(760, 420)
        self.configure(fg_color=("#f8fafc", "#141418"))
        self.transient(parent)
        self.grab_set()

        self.grid_rowconfigure(2, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # ---------------- 1. Cabeçalho explicativo colorido ----------------
        header = ctk.CTkFrame(self, fg_color=("#e2e8f0", "#1e1e26"), corner_radius=8, border_width=1, border_color=("#cbd5e1", "#343442"))
        header.grid(row=0, column=0, sticky="ew", padx=16, pady=(14, 6))
        header.grid_columnconfigure(0, weight=1)

        title_lbl = ctk.CTkLabel(
            header,
            text="🔒 Central de Regras e Bloqueios do NetGuard (Windows Firewall)",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=("#1d4ed8", "#60a5fa"),
        )
        title_lbl.grid(row=0, column=0, padx=14, pady=(10, 2), sticky="w")

        desc_lbl = ctk.CTkLabel(
            header,
            text="Todos os programas e endereços IP bloqueados por você são salvos permanentemente e sincronizados com o Windows Defender Firewall. Mesmo que o aplicativo seja fechado e aberto novamente, seus bloqueios continuam ativos e listados abaixo.",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=("gray25", "#d4d4d8"),
            wraplength=840,
            justify="left",
        )
        desc_lbl.grid(row=1, column=0, padx=14, pady=(0, 10), sticky="w")

        # ---------------- 1.1 Aviso de Modo Não-Elevado (se aplicável) ----------------
        if not is_admin():
            admin_warn = ctk.CTkFrame(self, fg_color=("#fef3c7", "#2e1c07"), corner_radius=8, border_width=1, border_color=("#f59e0b", "#92400e"))
            admin_warn.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 6))
            admin_warn.grid_columnconfigure(0, weight=1)

            warn_txt = ctk.CTkLabel(
                admin_warn,
                text="⚠️ Modo Usuário Padrão: Seus bloqueios continuam ativos no Windows Defender Firewall. Porém, para desbloquear itens ou criar novos bloqueios, são necessários privilégios de Administrador.",
                font=ctk.CTkFont(size=11, weight="bold"),
                text_color=("#92400e", "#fde68a"),
                wraplength=640,
                justify="left",
            )
            warn_txt.grid(row=0, column=0, padx=12, pady=6, sticky="w")

            elev_win_btn = ctk.CTkButton(
                admin_warn,
                text="⚡ Elevar para Administrador",
                font=ctk.CTkFont(size=11, weight="bold"),
                fg_color="#f59e0b",
                hover_color="#d97706",
                text_color="black",
                height=28,
                command=self._elevate_from_window,
            )
            elev_win_btn.grid(row=0, column=1, padx=12, pady=6, sticky="e")

        # ---------------- 2. Lista de regras (Treeview) ----------------
        table_frame = ctk.CTkFrame(self, corner_radius=8, fg_color=("#ffffff", "#18181b"))
        table_frame.grid(row=2, column=0, sticky="nsew", padx=16, pady=4)
        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)

        cols = ("rule_name", "target_type", "target_value", "direction", "enabled", "created_at")
        self.rules_tree = ttk.Treeview(table_frame, columns=cols, show="headings", selectmode="browse")

        self.rules_tree.heading("rule_name", text="Nome da Regra no Firewall")
        self.rules_tree.heading("target_type", text="Tipo")
        self.rules_tree.heading("target_value", text="Alvo Bloqueado (Caminho Executável ou IP)")
        self.rules_tree.heading("direction", text="Ação")
        self.rules_tree.heading("enabled", text="Estado")
        self.rules_tree.heading("created_at", text="Registrado Em")

        self.rules_tree.column("rule_name", width=220, anchor="w")
        self.rules_tree.column("target_type", width=130, anchor="center")
        self.rules_tree.column("target_value", width=280, anchor="w")
        self.rules_tree.column("direction", width=120, anchor="center")
        self.rules_tree.column("enabled", width=75, anchor="center")
        self.rules_tree.column("created_at", width=125, anchor="center")

        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.rules_tree.yview)
        hsb = ttk.Scrollbar(table_frame, orient="horizontal", command=self.rules_tree.xview)
        self.rules_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.rules_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        # ---------------- 3. Barra de botões inferior ----------------
        btn_bar = ctk.CTkFrame(self, fg_color="transparent")
        btn_bar.grid(row=3, column=0, sticky="ew", padx=16, pady=(6, 14))

        self.unblock_btn = ctk.CTkButton(
            btn_bar,
            text="🔓 Desbloquear Selecionado (Restaurar Internet)",
            fg_color="#10b981",
            hover_color="#059669",
            text_color="#ffffff",
            font=ctk.CTkFont(size=13, weight="bold"),
            height=38,
            command=self._unblock_selected,
        )
        self.unblock_btn.pack(side="left", padx=(0, 10))

        self.refresh_btn = ctk.CTkButton(
            btn_bar,
            text="🔄 Atualizar Lista",
            fg_color=("gray75", "#272732"),
            hover_color=("gray65", "#3f3f4e"),
            text_color=("gray10", "gray90"),
            font=ctk.CTkFont(size=12, weight="bold"),
            height=38,
            command=self.load_rules,
        )
        self.refresh_btn.pack(side="left")

        self.count_lbl = ctk.CTkLabel(
            btn_bar,
            text="",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#f59e0b",
        )
        self.count_lbl.pack(side="left", padx=16)

        close_btn = ctk.CTkButton(
            btn_bar,
            text="Fechar Janela",
            width=110,
            height=38,
            fg_color=("gray75", "#272732"),
            hover_color=("gray65", "#3f3f4e"),
            text_color=("gray10", "gray90"),
            font=ctk.CTkFont(size=12, weight="bold"),
            command=self.destroy,
        )
        close_btn.pack(side="right")

        self.load_rules()

    def _elevate_from_window(self):
        """Solicita elevação de UAC a partir do gerenciador de bloqueios."""
        self.destroy()
        self.parent_app._handle_request_elevation()

    def load_rules(self):
        self.rules_tree.delete(*self.rules_tree.get_children())
        rules: List[FirewallRuleItem] = list_netguard_rules()
        for r in rules:
            self.rules_tree.insert(
                "",
                "end",
                values=(r.rule_name, r.target_type, r.target_value, r.direction, r.enabled, r.created_at or "-"),
            )
        self.count_lbl.configure(
            text=f"🔒 {len(rules)} bloqueio(s) ativo(s)" if rules else "✅ Nenhum bloqueio ativo no momento"
        )

    def _unblock_selected(self):
        sel = self.rules_tree.selection()
        if not sel:
            show_modern_status(
                parent=self,
                title="Selecione uma Regra",
                header_badge="ℹ️ NENHUM ITEM SELECIONADO",
                header_title="Escolha qual bloqueio deseja remover",
                fields=[],
                explanation="Clique em uma das linhas da tabela acima antes de clicar no botão '🔓 Desbloquear Selecionado'.",
                status_type="info",
            )
            return

        vals = self.rules_tree.item(sel[0], "values")
        rule_name, target_type, target_value = vals[0], vals[1], vals[2]

        if not is_admin():
            show_modern_status(
                parent=self,
                title="Elevação de Administrador Necessária",
                header_badge="🛡️ ELEVAÇÃO REQUERIDA",
                header_title="Permissão de Administrador necessária para desbloquear",
                fields=[
                    ("🛡️ Regra Alvo", str(rule_name), "#f59e0b"),
                    ("🎯 Alvo", str(target_value), "#60a5fa"),
                ],
                explanation="O Windows Defender Firewall exige privilégios de Administrador para remover regras de bloqueio do sistema.",
                footer_tip="⚡ Clique no botão 'Executar como Administrador' para reiniciar com acesso total.",
                status_type="warning",
            )
            return

        ok, msg = remove_netguard_rule(rule_name)
        if ok:
            show_modern_status(
                parent=self,
                title="Acesso Restaurado",
                header_badge="🔓 DESBLOQUEIO CONCLUÍDO COM SUCESSO",
                header_title="A regra de bloqueio foi removida do Firewall!",
                fields=[
                    ("🎯 Alvo Liberado", str(target_value), "#10b981"),
                    ("📂 Tipo", str(target_type), "#60a5fa"),
                    ("🛡️ Regra Removida", str(rule_name), "#a1a1aa"),
                ],
                explanation="O programa ou endereço IP selecionado já pode voltar a se comunicar normalmente pela internet.",
                status_type="success",
            )
            self.load_rules()
        else:
            show_modern_status(
                parent=self,
                title="Erro ao Desbloquear",
                header_badge="❌ FALHA AO REMOVER REGRA",
                header_title="Não foi possível remover o bloqueio do Firewall",
                fields=[("🛡️ Regra", str(rule_name), "#ef4444")],
                explanation=msg,
                footer_tip="💡 Certifique-se de que o NetGuard está sendo executado como Administrador.",
                status_type="error",
            )


class NetGuardApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("NetGuard 2.0 — Cibersegurança & Monitor de Rede  |  Desenvolvido por Ronan Adriel Zenatti (ronanzenatti@gmail.com)")
        self.geometry("1380x850")
        self.minsize(1080, 670)

        # Estado da aplicação
        self.connections_data: List[ConnectionItem] = []
        self.filtered_data: List[ConnectionItem] = []
        self.row_map: Dict[str, ConnectionItem] = {}
        self.selected_conn: Optional[ConnectionItem] = None
        self._active_context_menu: Optional[ModernContextMenu] = None

        self.is_elevated: bool = is_admin()
        self.auto_refresh_enabled: bool = True
        self.hide_noise_enabled: bool = False
        self.refresh_interval_ms: int = 3000
        self.is_fetching: bool = False
        self.sort_column: str = "risk"
        self.sort_descending: bool = False
        self._scheduled_refresh_id: Optional[str] = None

        # Construção da Interface
        self._setup_ui()
        self._configure_treeview_styles()

        # Iniciar primeira coleta
        self.trigger_refresh(immediate=True)

    def _setup_ui(self):
        """Monta a estrutura visual completa do NetGuard 2.0."""
        self.grid_rowconfigure(2, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # ---------------- 1. Top Header ----------------
        self.header_frame = ctk.CTkFrame(self, corner_radius=0, fg_color=("gray90", "#141417"))
        self.header_frame.grid(row=0, column=0, sticky="ew")
        self.header_frame.grid_columnconfigure(1, weight=1)

        self.logo_label = ctk.CTkLabel(
            self.header_frame,
            text="🛡️ NetGuard 2.0",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color=("#1d4ed8", "#60a5fa"),
        )
        self.logo_label.grid(row=0, column=0, padx=(18, 8), pady=10, sticky="w")

        self.subtitle_label = ctk.CTkLabel(
            self.header_frame,
            text="|  Análise de Cibersegurança, Privacidade & Dados Brutos de Rede",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=("gray35", "gray65"),
        )
        self.subtitle_label.grid(row=0, column=1, padx=0, pady=10, sticky="w")

        # Botão Central de Bloqueios do Firewall
        self.fw_manager_btn = ctk.CTkButton(
            self.header_frame,
            text="🧱 Gerenciar Bloqueios (Firewall)",
            height=32,
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color=("#dc2626", "#991b1b"),
            hover_color=("#b91c1c", "#7f1d1d"),
            text_color="white",
            command=self._open_firewall_manager,
        )
        self.fw_manager_btn.grid(row=0, column=2, padx=(8, 6), pady=10, sticky="e")

        # Badge de Elevação / UAC
        self._setup_elevation_badge(self.header_frame)

        # Botão Alternar Tema
        self.theme_btn = ctk.CTkButton(
            self.header_frame,
            text="🌓 Tema",
            width=75,
            height=32,
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color=("gray80", "#27272a"),
            hover_color=("gray70", "#3f3f46"),
            text_color=("gray10", "gray90"),
            command=self._toggle_theme,
        )
        self.theme_btn.grid(row=0, column=4, padx=(6, 6), pady=10, sticky="e")

        # Botão Sobre / Créditos do Autor
        self.about_btn = ctk.CTkButton(
            self.header_frame,
            text="👨‍💻 Autor",
            width=80,
            height=32,
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color=("#dbeafe", "#1e3a8a"),
            hover_color=("#bfdbfe", "#1d4ed8"),
            text_color=("#1e40af", "#93c5fd"),
            command=self._show_about_author,
        )
        self.about_btn.grid(row=0, column=5, padx=(0, 18), pady=10, sticky="e")

        # ---------------- 2. Painel de Métricas e Barra de Ferramentas ----------------
        self.control_container = ctk.CTkFrame(self, fg_color="transparent")
        self.control_container.grid(row=1, column=0, sticky="ew", padx=16, pady=(8, 4))
        self.control_container.grid_columnconfigure(0, weight=1)

        self._setup_stats_cards(self.control_container)
        self._setup_toolbar(self.control_container)

        # ---------------- 3. Tabela Principal (Dados Brutos + Cibersegurança) ----------------
        self.table_container = ctk.CTkFrame(self, corner_radius=8, fg_color=("white", "#18181b"))
        self.table_container.grid(row=2, column=0, sticky="nsew", padx=16, pady=(4, 6))
        self.table_container.grid_rowconfigure(0, weight=1)
        self.table_container.grid_columnconfigure(0, weight=1)

        self._setup_table(self.table_container)

        # ---------------- 4. Painel Inspetor Duplo (Leigo + Estudante + Firewall) ----------------
        self._setup_inspector_panel()

        # ---------------- 5. Barra de Status Inferior & Créditos do Desenvolvedor ----------------
        self.status_bar = ctk.CTkFrame(self, height=32, corner_radius=0, fg_color=("gray92", "#141417"))
        self.status_bar.grid(row=4, column=0, sticky="ew")
        self.status_bar.grid_columnconfigure(1, weight=1)

        self.status_text = ctk.CTkLabel(
            self.status_bar,
            text="Iniciando motor de análise de cibersegurança...",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=("gray30", "#a1a1aa"),
        )
        self.status_text.grid(row=0, column=0, padx=16, pady=4, sticky="w")

        self.author_badge = ctk.CTkButton(
            self.status_bar,
            text="👨‍💻 Desenvolvido por Ronan Adriel Zenatti  •  ✉️ ronanzenatti@gmail.com",
            height=22,
            corner_radius=6,
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color=("gray85", "#1f2430"),
            hover_color=("gray75", "#2d3548"),
            text_color=("#1d4ed8", "#38bdf8"),
            command=self._show_about_author,
        )
        self.author_badge.grid(row=0, column=1, padx=10, pady=4)

        self.selection_text = ctk.CTkLabel(
            self.status_bar,
            text="💡 Clique em qualquer linha para ver detalhes e bloquear conexões",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=("#1d4ed8", "#60a5fa"),
        )
        self.selection_text.grid(row=0, column=2, padx=16, pady=4, sticky="e")

    def _setup_elevation_badge(self, parent):
        self.elevation_frame = ctk.CTkFrame(parent, fg_color="transparent")
        self.elevation_frame.grid(row=0, column=3, padx=6, pady=10, sticky="e")

        if self.is_elevated:
            self.elev_badge = ctk.CTkLabel(
                self.elevation_frame,
                text="🛡️ Administrador (Acesso Total)",
                font=ctk.CTkFont(size=12, weight="bold"),
                text_color="#10b981",
                fg_color=("#d1fae5", "#064e3b"),
                corner_radius=6,
                padx=10,
                pady=5,
            )
            self.elev_badge.pack(side="right")
        else:
            self.elev_btn = ctk.CTkButton(
                self.elevation_frame,
                text="⚡ Executar como Administrador",
                font=ctk.CTkFont(size=12, weight="bold"),
                fg_color="#f59e0b",
                hover_color="#d97706",
                text_color="black",
                height=32,
                corner_radius=6,
                command=self._handle_request_elevation,
            )
            self.elev_btn.pack(side="right", padx=(6, 0))

    def _setup_stats_cards(self, parent):
        self.cards_frame = ctk.CTkFrame(parent, fg_color="transparent")
        self.cards_frame.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        for col in range(6):
            self.cards_frame.grid_columnconfigure(col, weight=1)

        self.card_total = self._create_card(self.cards_frame, 0, "Total de Conexões", "0", "#3b82f6")
        self.card_safe = self._create_card(self.cards_frame, 1, "🟢 Seguras / Confiáveis", "0", "#10b981")
        self.card_telemetry = self._create_card(self.cards_frame, 2, "🟡 Telemetria / Atenção", "0", "#f59e0b")
        self.card_suspicious = self._create_card(self.cards_frame, 3, "🔴 Suspeitas / Alerta", "0", "#ef4444")
        self.card_listen = self._create_card(self.cards_frame, 4, "👂 Portas em Escuta", "0", "#38bdf8")
        self.card_apps = self._create_card(self.cards_frame, 5, "📦 Executáveis Únicos", "0", "#a855f7")

    def _create_card(self, parent, col, title, value, color_hex):
        frame = ctk.CTkFrame(parent, corner_radius=8, fg_color=("gray95", "#1e1e26"), border_width=1, border_color=("gray85", "#2e2e3a"))
        frame.grid(row=0, column=col, padx=3, pady=0, sticky="nsew")

        lbl_title = ctk.CTkLabel(
            frame,
            text=title,
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=("gray35", "#a1a1aa"),
        )
        lbl_title.pack(anchor="w", padx=12, pady=(6, 0))

        lbl_value = ctk.CTkLabel(
            frame,
            text=value,
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color=color_hex,
        )
        lbl_value.pack(anchor="w", padx=12, pady=(0, 6))
        return lbl_value

    def _setup_toolbar(self, parent):
        self.toolbar_frame = ctk.CTkFrame(parent, fg_color="transparent")
        self.toolbar_frame.grid(row=1, column=0, sticky="ew")
        self.toolbar_frame.grid_columnconfigure(0, weight=1)

        # Busca em tempo real
        self.search_entry = ctk.CTkEntry(
            self.toolbar_frame,
            placeholder_text="🔍 Filtrar por executável, PID, IP, empresa (Google, Microsoft, Meta) ou porta...",
            height=34,
            font=ctk.CTkFont(size=12),
        )
        self.search_entry.grid(row=0, column=0, sticky="ew", padx=(0, 8), pady=2)
        self.search_entry.bind("<KeyRelease>", lambda e: self.apply_filters())

        # Filtros Rápidos de Cibersegurança e Protocolo
        self.filter_segmented = ctk.CTkSegmentedButton(
            self.toolbar_frame,
            values=["Todos", "⚠️ Telemetria/Atenção", "🔴 Suspeitos", "TCP", "UDP", "LISTEN", "ESTABLISHED"],
            command=lambda val: self.apply_filters(),
            height=34,
            font=ctk.CTkFont(size=11, weight="bold"),
        )
        self.filter_segmented.set("Todos")
        self.filter_segmented.grid(row=0, column=1, padx=(0, 8), pady=2)

        # Switch Modo Simplificado vs Dados Brutos Completos
        self.noise_switch = ctk.CTkSwitch(
            self.toolbar_frame,
            text="Ocultar Ruído (TIME_WAIT/Local)",
            font=ctk.CTkFont(size=11, weight="bold"),
            command=self._on_noise_switch_changed,
        )
        self.noise_switch.grid(row=0, column=2, padx=(0, 8), pady=2)

        # Auto-refresh
        self.auto_switch = ctk.CTkSwitch(
            self.toolbar_frame,
            text="Auto",
            width=60,
            font=ctk.CTkFont(size=11, weight="bold"),
            command=self._on_auto_switch_changed,
        )
        self.auto_switch.select()
        self.auto_switch.grid(row=0, column=3, padx=(0, 6), pady=2)

        self.interval_combo = ctk.CTkComboBox(
            self.toolbar_frame,
            values=["1s", "2s", "3s", "5s", "10s"],
            width=68,
            height=34,
            command=self._on_interval_changed,
        )
        self.interval_combo.set("3s")
        self.interval_combo.grid(row=0, column=4, padx=(0, 6), pady=2)

        self.refresh_btn = ctk.CTkButton(
            self.toolbar_frame,
            text="🔄 Atualizar",
            width=95,
            height=34,
            font=ctk.CTkFont(size=12, weight="bold"),
            command=lambda: self.trigger_refresh(immediate=True),
        )
        self.refresh_btn.grid(row=0, column=5, padx=(0, 6), pady=2)

        self.export_btn = ctk.CTkButton(
            self.toolbar_frame,
            text="📥 CSV",
            width=70,
            height=34,
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color=("gray80", "#27272a"),
            hover_color=("gray70", "#3f3f46"),
            text_color=("gray10", "gray90"),
            command=self._export_csv,
        )
        self.export_btn.grid(row=0, column=6, padx=0, pady=2)

    def _setup_table(self, parent):
        columns = (
            "risk",
            "pid",
            "name",
            "proto",
            "local_ip",
            "local_port",
            "remote_ip",
            "remote_port",
            "org",
            "status",
            "username",
            "exe_path",
        )

        self.tree = ttk.Treeview(
            parent,
            columns=columns,
            show="headings",
            selectmode="browse",
        )

        col_configs = [
            ("risk", "Avaliação", 130, "w"),
            ("pid", "PID", 65, "center"),
            ("name", "Executável", 150, "w"),
            ("proto", "Proto", 60, "center"),
            ("local_ip", "Endereço Local", 115, "w"),
            ("local_port", "P. Local", 70, "center"),
            ("remote_ip", "Endereço Remoto", 120, "w"),
            ("remote_port", "P. Remota", 75, "center"),
            ("org", "Destino / Organização (Quem é?)", 215, "w"),
            ("status", "Status Socket", 100, "center"),
            ("username", "Usuário", 130, "w"),
            ("exe_path", "Caminho Bruto do Executável", 280, "w"),
        ]

        for col_id, col_name, width, align in col_configs:
            self.tree.heading(
                col_id,
                text=col_name,
                anchor=align,
                command=lambda c=col_id: self._sort_by_column(c),
            )
            self.tree.column(col_id, width=width, minwidth=55, anchor=align)

        vsb = ttk.Scrollbar(parent, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(parent, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        self.tree.bind("<<TreeviewSelect>>", self._on_row_selected)
        self.tree.bind("<Button-3>", self._show_context_menu)
        self.tree.bind("<Double-1>", lambda e: self._on_open_folder())

        # Fechar o menu de contexto automaticamente apenas se o clique for fora dele
        self.bind_all("<Button-1>", self._on_global_left_click, add="+")
        self.bind("<Configure>", lambda e: self._close_active_context_menu(), add="+")

    def _setup_inspector_panel(self):
        """
        Painel inferior dividido em 3 seções com bordas e cores de destaque:
        1. Explicação em Português Claro (Para Leigos)
        2. Dados Técnicos & Forenses (Para Estudantes de Cibersegurança)
        3. Botões de Ação e Bloqueio no Firewall
        """
        self.inspector_frame = ctk.CTkFrame(
            self,
            corner_radius=8,
            fg_color=("gray94", "#18181f"),
            border_width=1,
            border_color=("gray80", "#2e2e3a"),
        )
        self.inspector_frame.grid(row=3, column=0, sticky="ew", padx=16, pady=(2, 6))
        self.inspector_frame.grid_columnconfigure(0, weight=5)
        self.inspector_frame.grid_columnconfigure(1, weight=4)
        self.inspector_frame.grid_columnconfigure(2, weight=3)

        # --- Coluna 0: Tradutor para Leigos ---
        self.layman_box = ctk.CTkFrame(
            self.inspector_frame,
            corner_radius=6,
            fg_color=("white", "#22222c"),
            border_width=1,
            border_color=("gray85", "#323242"),
        )
        self.layman_box.grid(row=0, column=0, sticky="nsew", padx=(8, 4), pady=8)

        self.insp_title_lbl = ctk.CTkLabel(
            self.layman_box,
            text="💡 Selecione qualquer conexão na tabela acima para analisá-la",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=("#1d4ed8", "#60a5fa"),
            anchor="w",
        )
        self.insp_title_lbl.pack(fill="x", padx=12, pady=(8, 2))

        self.insp_explain_lbl = ctk.CTkLabel(
            self.layman_box,
            text="Ao clicar em uma linha, explicaremos em português claro o que é o programa, com quem ele está conversando e se é seguro bloqueá-lo.",
            font=ctk.CTkFont(size=12),
            text_color=("gray20", "#e4e4e7"),
            justify="left",
            anchor="w",
            wraplength=520,
        )
        self.insp_explain_lbl.pack(fill="x", padx=12, pady=2)

        self.insp_advice_lbl = ctk.CTkLabel(
            self.layman_box,
            text="",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#10b981",
            justify="left",
            anchor="w",
            wraplength=520,
        )
        self.insp_advice_lbl.pack(fill="x", padx=12, pady=(2, 8))

        # --- Coluna 1: Visão Técnica / Forense (Estudantes de Cibersegurança) ---
        self.tech_box = ctk.CTkFrame(
            self.inspector_frame,
            corner_radius=6,
            fg_color=("white", "#22222c"),
            border_width=1,
            border_color=("gray85", "#323242"),
        )
        self.tech_box.grid(row=0, column=1, sticky="nsew", padx=4, pady=8)

        tech_header = ctk.CTkFrame(self.tech_box, fg_color="transparent")
        tech_header.pack(fill="x", padx=12, pady=(8, 2))

        ctk.CTkLabel(
            tech_header,
            text="🔬 Telemetria Técnica (Cybersec)",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=("#7c3aed", "#c084fc"),
        ).pack(side="left")

        self.sha_btn = ctk.CTkButton(
            tech_header,
            text="🔑 SHA-256",
            width=90,
            height=24,
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color=("#ede9fe", "#3b235a"),
            hover_color=("#ddd6fe", "#583387"),
            text_color=("#5b21b6", "#e9d5ff"),
            command=self._on_calculate_sha256,
        )
        self.sha_btn.pack(side="right", padx=(4, 0))

        self.open_folder_btn = ctk.CTkButton(
            tech_header,
            text="📁 Abrir Pasta",
            width=95,
            height=24,
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color=("#dbeafe", "#1e3a8a"),
            hover_color=("#bfdbfe", "#1d4ed8"),
            text_color=("#1e40af", "#93c5fd"),
            command=self._on_open_folder,
        )
        self.open_folder_btn.pack(side="right")

        self.insp_tech_lbl = ctk.CTkLabel(
            self.tech_box,
            text="Aguardando seleção de socket para exibir análise técnica, rDNS (PTR), caminho bruto e contexto MITRE ATT&CK...",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=("gray25", "#d4d4d8"),
            justify="left",
            anchor="w",
            wraplength=410,
        )
        self.insp_tech_lbl.pack(fill="x", padx=12, pady=(2, 8))

        # --- Coluna 2: Ações Rápidas de Firewall e Processo ---
        self.actions_box = ctk.CTkFrame(
            self.inspector_frame,
            corner_radius=6,
            fg_color=("white", "#22222c"),
            border_width=1,
            border_color=("gray85", "#323242"),
        )
        self.actions_box.grid(row=0, column=2, sticky="nsew", padx=(4, 8), pady=8)
        self.actions_box.grid_columnconfigure((0, 1), weight=1)

        ctk.CTkLabel(
            self.actions_box,
            text="🛡️ Ações de Bloqueio & Resposta",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=("#dc2626", "#f87171"),
        ).grid(row=0, column=0, columnspan=2, padx=10, pady=(8, 4), sticky="w")

        self.btn_block_app = ctk.CTkButton(
            self.actions_box,
            text="🚫 Bloquear Programa (.exe) no Firewall",
            fg_color="#dc2626",
            hover_color="#b91c1c",
            text_color="#ffffff",
            font=ctk.CTkFont(size=12, weight="bold"),
            height=32,
            command=self._on_block_executable,
        )
        self.btn_block_app.grid(row=1, column=0, columnspan=2, padx=8, pady=3, sticky="ew")

        self.btn_block_ip = ctk.CTkButton(
            self.actions_box,
            text="🎯 Bloquear Este IP",
            fg_color="#d97706",
            hover_color="#b45309",
            text_color="#ffffff",
            font=ctk.CTkFont(size=11, weight="bold"),
            height=32,
            command=self._on_block_ip,
        )
        self.btn_block_ip.grid(row=2, column=0, padx=(8, 3), pady=(3, 8), sticky="ew")

        self.btn_kill_proc = ctk.CTkButton(
            self.actions_box,
            text="⚠️ Encerrar PID",
            fg_color=("#e2e8f0", "#323242"),
            hover_color="#991b1b",
            text_color=("gray10", "#f4f4f5"),
            font=ctk.CTkFont(size=11, weight="bold"),
            height=32,
            command=self._on_kill_process,
        )
        self.btn_kill_proc.grid(row=2, column=1, padx=(3, 8), pady=(3, 8), sticky="ew")

    def _configure_treeview_styles(self):
        style = ttk.Style()
        style.theme_use("clam")

        is_dark = ctk.get_appearance_mode() == "Dark"

        bg_color = "#18181b" if is_dark else "#ffffff"
        fg_color = "#f4f4f5" if is_dark else "#09090b"
        header_bg = "#272730" if is_dark else "#e4e4e7"
        header_fg = "#fafafa" if is_dark else "#18181b"
        select_bg = "#2563eb" if is_dark else "#3b82f6"
        row_alt = "#202027" if is_dark else "#f8fafc"

        style.configure(
            "Treeview",
            background=bg_color,
            foreground=fg_color,
            fieldbackground=bg_color,
            rowheight=27,
            font=("Segoe UI", 9),
            borderwidth=0,
        )
        style.map(
            "Treeview",
            background=[("selected", select_bg)],
            foreground=[("selected", "#ffffff")],
        )

        style.configure(
            "Treeview.Heading",
            background=header_bg,
            foreground=header_fg,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
            padding=(5, 6),
        )
        style.map(
            "Treeview.Heading",
            background=[("active", "#3f3f4e" if is_dark else "#d4d4d8")],
        )

        # Tags visuais por nível de risco
        self.tree.tag_configure("evenrow", background=bg_color)
        self.tree.tag_configure("oddrow", background=row_alt)
        self.tree.tag_configure(
            "telemetry_row",
            background="#2c2410" if is_dark else "#fef3c7",
            foreground="#fcd34d" if is_dark else "#92400e",
        )
        self.tree.tag_configure(
            "critical_row",
            background="#3b1219" if is_dark else "#fee2e2",
            foreground="#fca5a5" if is_dark else "#991b1b",
        )

    def _close_active_context_menu(self):
        if self._active_context_menu and self._active_context_menu.winfo_exists():
            self._active_context_menu.close_menu()
        self._active_context_menu = None

    def _on_global_left_click(self, event):
        if self._active_context_menu and self._active_context_menu.winfo_exists():
            if not self._active_context_menu.is_point_inside(event.x_root, event.y_root):
                self._close_active_context_menu()

    def _show_context_menu(self, event):
        """Abre o menu de contexto moderno CustomTkinter ao clicar com o botão direito."""
        self._close_active_context_menu()

        row_id = self.tree.identify_row(event.y)
        if not row_id:
            return

        self.tree.selection_set(row_id)
        self._on_row_selected()

        if not self.selected_conn:
            return

        conn = self.selected_conn
        proc_header = f"{conn.process_name} (PID: {conn.pid or '-'})"
        badge_sub = f"{conn.security.risk_badge}  •  {conn.security.destination_org}"

        menu_items = [
            ("🚫 Bloquear Programa (.exe) no Firewall", self._on_block_executable, "#f87171", "#450a0a", True),
            ("🎯 Bloquear Apenas Este IP no Firewall", self._on_block_ip, "#fbbf24", "#451a03", True),
            None,
            ("📁 Abrir Pasta do Executável no Explorer", self._on_open_folder, "#60a5fa", "#172554", True),
            ("🔑 Calcular e Copiar Hash SHA-256", self._on_calculate_sha256, "#c084fc", "#3b0764", True),
            None,
            ("📋 Copiar Caminho Completo do .exe", self._on_copy_path, "#e4e4e7", "#272732", False),
            ("📋 Copiar Endereço IP:Porta Remoto", self._on_copy_remote, "#e4e4e7", "#272732", False),
            ("📋 Copiar Linha Completa (Dados Brutos)", self._on_copy_row, "#e4e4e7", "#272732", False),
            None,
            ("⚠️ Encerrar Processo Agora (Kill PID)", self._on_kill_process, "#fca5a5", "#7f1d1d", True),
        ]

        self._active_context_menu = ModernContextMenu(
            parent=self,
            x=event.x_root,
            y=event.y_root,
            process_title=proc_header,
            risk_badge=badge_sub,
            items=menu_items,
        )

    # ---------------- Coleta em Background ----------------

    def trigger_refresh(self, immediate: bool = False):
        # Se o menu de contexto estiver aberto na tela, adiar o auto-refresh para não atrapalhar o clique do usuário
        if not immediate and self._active_context_menu and self._active_context_menu.winfo_exists():
            if self.auto_refresh_enabled:
                self._schedule_next_refresh()
            return

        if self.is_fetching and not immediate:
            return

        self.is_fetching = True
        self.refresh_btn.configure(text="⏳...", state="disabled")

        worker = threading.Thread(target=self._fetch_connections_worker, daemon=True)
        worker.start()

    def _fetch_connections_worker(self):
        conns = get_active_connections()
        self.after(0, self._on_connections_fetched, conns)

    def _on_connections_fetched(self, conns: List[ConnectionItem]):
        self.connections_data = conns
        self.is_fetching = False
        self.refresh_btn.configure(text="🔄 Atualizar", state="normal")

        self._update_stats()
        self.apply_filters()

        now_str = datetime.datetime.now().strftime("%H:%M:%S")
        self.status_text.configure(
            text=f"Mostrando {len(self.filtered_data)} de {len(self.connections_data)} conexões totais  |  Última varredura: {now_str}"
        )

        if self.auto_refresh_enabled:
            self._schedule_next_refresh()

    def _schedule_next_refresh(self):
        if self._scheduled_refresh_id:
            self.after_cancel(self._scheduled_refresh_id)
        self._scheduled_refresh_id = self.after(self.refresh_interval_ms, self.trigger_refresh)

    def _update_stats(self):
        total = len(self.connections_data)
        safe_count = sum(1 for c in self.connections_data if c.security.risk_level == "SAFE")
        telem_count = sum(1 for c in self.connections_data if c.security.risk_level in ("TELEMETRY", "WARNING"))
        crit_count = sum(1 for c in self.connections_data if c.security.risk_level == "CRITICAL")
        listen_count = sum(1 for c in self.connections_data if "LISTEN" in c.status.upper())
        unique_apps = len({c.process_name for c in self.connections_data if c.process_name})

        self.card_total.configure(text=f"{total:,}")
        self.card_safe.configure(text=f"{safe_count:,}")
        self.card_telemetry.configure(text=f"{telem_count:,}")
        self.card_suspicious.configure(text=f"{crit_count:,}")
        self.card_listen.configure(text=f"{listen_count:,}")
        self.card_apps.configure(text=f"{unique_apps:,}")

    # ---------------- Filtros e Ordenação ----------------

    def apply_filters(self):
        search_query = self.search_entry.get().strip().lower()
        active_filter = self.filter_segmented.get()

        filtered: List[ConnectionItem] = []

        for conn in self.connections_data:
            if self.hide_noise_enabled:
                if conn.status.upper() in ("TIME_WAIT", "CLOSE_WAIT"):
                    continue
                if conn.remote_ip in ("127.0.0.1", "::1", "-", "0.0.0.0", "::"):
                    continue

            if active_filter == "⚠️ Telemetria/Atenção" and conn.security.risk_level not in ("TELEMETRY", "WARNING", "CRITICAL"):
                continue
            if active_filter == "🔴 Suspeitos" and conn.security.risk_level != "CRITICAL":
                continue
            if active_filter == "TCP" and conn.proto != "TCP":
                continue
            if active_filter == "UDP" and conn.proto != "UDP":
                continue
            if active_filter == "LISTEN" and "LISTEN" not in conn.status.upper():
                continue
            if active_filter == "ESTABLISHED" and "ESTABLISHED" not in conn.status.upper():
                continue

            if search_query:
                match_text = (
                    f"{conn.security.risk_badge} {conn.pid} {conn.process_name} "
                    f"{conn.local_ip}:{conn.local_port} {conn.remote_ip}:{conn.remote_port} "
                    f"{conn.security.destination_org} {conn.status} {conn.exe_path} {conn.username}"
                ).lower()
                if search_query not in match_text:
                    continue

            filtered.append(conn)

        self.filtered_data = filtered
        self._populate_tree()

    def _populate_tree(self):
        self._sort_data_in_place()

        prev_key = None
        if self.selected_conn:
            prev_key = (
                self.selected_conn.pid,
                self.selected_conn.local_port,
                self.selected_conn.remote_ip,
                self.selected_conn.remote_port,
            )

        self.tree.delete(*self.tree.get_children())
        self.row_map.clear()

        selected_item_id = None

        for index, conn in enumerate(self.filtered_data):
            if conn.security.risk_level == "CRITICAL":
                row_tag = "critical_row"
            elif conn.security.risk_level == "TELEMETRY":
                row_tag = "telemetry_row"
            else:
                row_tag = "evenrow" if index % 2 == 0 else "oddrow"

            item_id = self.tree.insert(
                "",
                "end",
                values=(
                    conn.security.risk_badge,
                    conn.pid or "-",
                    conn.process_name,
                    conn.proto,
                    conn.local_ip,
                    conn.local_port,
                    conn.remote_ip,
                    conn.remote_port,
                    conn.security.destination_org,
                    conn.status,
                    conn.username,
                    conn.exe_path,
                ),
                tags=(row_tag,),
            )
            self.row_map[item_id] = conn

            curr_key = (conn.pid, conn.local_port, conn.remote_ip, conn.remote_port)
            if prev_key and curr_key == prev_key:
                selected_item_id = item_id

        if selected_item_id:
            self.tree.selection_set(selected_item_id)

    def _sort_by_column(self, col_id: str):
        if self.sort_column == col_id:
            self.sort_descending = not self.sort_descending
        else:
            self.sort_column = col_id
            self.sort_descending = False

        self._update_column_headers()
        self._populate_tree()

    def _update_column_headers(self):
        headers = {
            "risk": "Avaliação",
            "pid": "PID",
            "name": "Executável",
            "proto": "Proto",
            "local_ip": "Endereço Local",
            "local_port": "P. Local",
            "remote_ip": "Endereço Remoto",
            "remote_port": "P. Remota",
            "org": "Destino / Organização (Quem é?)",
            "status": "Status Socket",
            "username": "Usuário",
            "exe_path": "Caminho Bruto do Executável",
        }
        for cid, label in headers.items():
            if cid == self.sort_column:
                arrow = " ▼" if self.sort_descending else " ▲"
                self.tree.heading(cid, text=f"{label}{arrow}")
            else:
                self.tree.heading(cid, text=label)

    def _sort_data_in_place(self):
        risk_priority = {"CRITICAL": 0, "TELEMETRY": 1, "WARNING": 2, "SAFE": 3}

        def sort_key(item: ConnectionItem):
            if self.sort_column == "risk":
                return (risk_priority.get(item.security.risk_level, 9), item.process_name.lower())
            if self.sort_column == "pid":
                return item.pid or -1
            if self.sort_column == "name":
                return item.process_name.lower()
            if self.sort_column == "proto":
                return item.proto
            if self.sort_column == "local_ip":
                return item.local_ip
            if self.sort_column == "local_port":
                return item.local_port
            if self.sort_column == "remote_ip":
                return item.remote_ip
            if self.sort_column == "remote_port":
                try:
                    return int(item.remote_port)
                except Exception:
                    return 0
            if self.sort_column == "org":
                return item.security.destination_org.lower()
            if self.sort_column == "status":
                return item.status
            if self.sort_column == "username":
                return item.username.lower()
            if self.sort_column == "exe_path":
                return item.exe_path.lower()
            return 0

        self.filtered_data.sort(key=sort_key, reverse=self.sort_descending)

    # ---------------- Seleção e Painel Inspetor ----------------

    def _on_row_selected(self, event=None):
        selected = self.tree.selection()
        if not selected:
            return

        item_id = selected[0]
        conn = self.row_map.get(item_id)
        if not conn:
            return

        self.selected_conn = conn
        sec = conn.security

        if sec.risk_level == "CRITICAL":
            title_color = "#ef4444"
            advice_color = "#f87171"
        elif sec.risk_level == "TELEMETRY":
            title_color = "#f59e0b"
            advice_color = "#fbbf24"
        else:
            title_color = "#10b981"
            advice_color = "#34d399"

        self.insp_title_lbl.configure(
            text=f"{sec.risk_badge}  —  {sec.layman_title}",
            text_color=title_color,
        )
        self.insp_explain_lbl.configure(text=sec.layman_explanation)
        self.insp_advice_lbl.configure(text=sec.layman_advice, text_color=advice_color)

        rdns = ip_intel.get_rdns(conn.remote_ip) if conn.remote_ip not in ("-", "127.0.0.1", "::1") else "Localhost"
        tech_summary = (
            f"• Socket: {conn.proto} {conn.local_ip}:{conn.local_port} ➔ {conn.remote_ip}:{conn.remote_port} [{conn.status}]\n"
            f"• rDNS (PTR): {rdns} | Org: {sec.destination_org}\n"
            f"• Análise: {sec.technical_notes}"
        )
        self.insp_tech_lbl.configure(text=tech_summary)

        self.selection_text.configure(
            text=f"⚡ Selecionado: {conn.process_name} (PID: {conn.pid or '-'})  •  Destino: {sec.destination_org}"
        )

    # ---------------- Ações de Cibersegurança & Firewall (Com Diálogos Modernos) ----------------

    def _require_selection(self, action_name: str) -> Optional[ConnectionItem]:
        if not self.selected_conn:
            show_modern_status(
                parent=self,
                title="Nenhuma Conexão Selecionada",
                header_badge="ℹ️ SELEÇÃO NECESSÁRIA",
                header_title=f"Escolha uma linha na tabela para {action_name}",
                fields=[],
                explanation="Clique primeiro sobre qualquer conexão listada na tabela principal e tente novamente.",
                status_type="info",
            )
            return None
        return self.selected_conn

    def _on_block_executable(self):
        conn = self._require_selection("bloquear o programa")
        if not conn:
            return

        can_block, validation_msg, is_browser = validate_executable_block(conn.process_name, conn.exe_path)

        if not can_block:
            show_modern_status(
                parent=self,
                title="Trava de Segurança do NetGuard",
                header_badge="🛡️ PROTEÇÃO ANTI-ACIDENTE ATIVADA",
                header_title=f"O processo '{conn.process_name}' é protegido pelo sistema!",
                fields=[
                    ("📦 Processo Vital", conn.process_name, "#f59e0b"),
                    ("📂 Localização", conn.exe_path, "#a1a1aa"),
                    ("🚦 Classificação", conn.security.risk_badge, "#10b981"),
                ],
                explanation=(
                    f"Este executável faz parte do núcleo do Windows ou do seu Antivírus. "
                    f"Bloquear o arquivo '{conn.process_name}' inteiro poderia derrubar sua internet ou desativar atualizações de segurança."
                ),
                footer_tip="💡 Dica: Se você quiser cortar apenas a conexão com o servidor específico desta linha, clique no botão laranja '🎯 Bloquear Este IP'!",
                status_type="warning",
            )
            return

        # Diálogo Moderno de Confirmação de Bloqueio de Programa
        header_title = (
            f"Atenção: Você está prestes a bloquear seu navegador ({conn.process_name})!"
            if is_browser
            else f"Deseja bloquear o acesso à internet para '{conn.process_name}'?"
        )

        confirmed = ask_modern_confirmation(
            parent=self,
            title="Confirmar Bloqueio no Firewall",
            header_badge="🧱 BLOQUEIO DE PROGRAMA NO WINDOWS FIREWALL",
            header_title=header_title,
            fields=[
                ("📦 Programa Alvo", conn.process_name, "#f87171"),
                ("🔢 PID / Avaliação", f"PID {conn.pid or '-'}   •   {conn.security.risk_badge}", "#fbbf24"),
                ("🏢 Conectado a", conn.security.destination_org, "#38bdf8"),
                ("📂 Caminho do .exe", conn.exe_path, "#e4e4e7"),
            ],
            explanation=(
                "Ao confirmar, o Windows Defender Firewall impedirá imediatamente que este executável "
                "envie ou receba dados da internet."
            ),
            footer_tip="🔓 Como desfazer: Você pode desbloquear este programa quando quiser com 1 clique no botão '🧱 Gerenciar Bloqueios' no topo da tela.",
            confirm_text="🚫 Sim, Bloquear Programa",
            cancel_text="Cancelar",
            is_danger=True,
        )

        if confirmed:
            ok, result_msg = block_executable_in_firewall(conn.process_name, conn.exe_path)
            if ok:
                show_modern_status(
                    parent=self,
                    title="Bloqueio Ativado com Sucesso",
                    header_badge="✅ BLOQUEIO ATIVADO NO FIREWALL DO WINDOWS",
                    header_title=f"O programa '{conn.process_name}' foi bloqueado com sucesso!",
                    fields=[
                        ("🔒 Status no Firewall", "BLOQUEADO (Comunicação Externa Proibida)", "#10b981"),
                        ("📦 Programa Bloqueado", conn.process_name, "#f4f4f5"),
                        ("📂 Arquivo", conn.exe_path, "#a1a1aa"),
                    ],
                    explanation="A regra já está em vigor no Windows Defender Firewall. Este aplicativo não poderá mais enviar dados para fora do seu computador.",
                    footer_tip="🔓 Precisa liberar o programa novamente? Clique em '🧱 Gerenciar Bloqueios (Firewall)' no topo da janela.",
                    status_type="success",
                )
            else:
                show_modern_status(
                    parent=self,
                    title="Falha ao Bloquear Programa",
                    header_badge="❌ NÃO FOI POSSÍVEL CRIAR A REGRA NO FIREWALL",
                    header_title=f"O bloqueio de '{conn.process_name}' falhou",
                    fields=[
                        ("📦 Programa", conn.process_name, "#ef4444"),
                        ("⚠️ Motivo Técnico", result_msg, "#fca5a5"),
                    ],
                    explanation="O Windows Firewall exige privilégios de Administrador para adicionar novas regras de bloqueio.",
                    footer_tip="⚡ Solução: Clique no botão 'Executar como Administrador' no topo do NetGuard e tente novamente.",
                    status_type="error",
                )

    def _on_block_ip(self):
        conn = self._require_selection("bloquear o endereço IP")
        if not conn:
            return

        rip = conn.remote_ip

        if not rip or rip in ("-", "0.0.0.0", "::", "127.0.0.1", "::1"):
            show_modern_status(
                parent=self,
                title="Endereço Interno / Sem Servidor Externo",
                header_badge="🛡️ AÇÃO NÃO APLICÁVEL PARA CONEXÃO LOCAL",
                header_title="Esta linha não está conectada a um servidor da internet",
                fields=[
                    ("📦 Processo", conn.process_name, "#60a5fa"),
                    ("🏠 Endereço Atual", f"{rip} (Porta {conn.local_port} em estado {conn.status})", "#fbbf24"),
                ],
                explanation=(
                    "Esta linha representa apenas uma porta aguardando conexões (LISTEN) ou uma comunicação "
                    "interna dentro do seu próprio computador (Loopback 127.0.0.1), portanto não há um IP externo para bloquear."
                ),
                status_type="warning",
            )
            return

        confirmed = ask_modern_confirmation(
            parent=self,
            title="Confirmar Bloqueio de IP Remoto",
            header_badge="🎯 BLOQUEIO DE SERVIDOR / IP ESPECÍFICO",
            header_title=f"Deseja cortar toda comunicação com o IP {rip}?",
            fields=[
                ("🌐 Endereço IP Alvo", f"{rip}  (Porta {conn.remote_port})", "#fbbf24"),
                ("🏢 Empresa / Destino", conn.security.destination_org, "#38bdf8"),
                ("📦 Processo Utilizando", f"{conn.process_name} (PID: {conn.pid or '-'})", "#f4f4f5"),
            ],
            explanation=(
                "Ao confirmar, seu computador ficará proibido de enviar ou receber pacotes deste servidor específico, "
                "mas o programa continuará funcionando normalmente para outros endereços."
            ),
            footer_tip="🔓 Você pode desbloquear este IP a qualquer momento em '🧱 Gerenciar Bloqueios (Firewall)'.",
            confirm_text="🎯 Sim, Bloquear Este IP",
            cancel_text="Cancelar",
            is_danger=False,
        )

        if confirmed:
            ok, result_msg = block_ip_in_firewall(rip, conn.process_name)
            if ok:
                show_modern_status(
                    parent=self,
                    title="Endereço IP Bloqueado",
                    header_badge="✅ SERVIDOR BLOQUEADO COM SUCESSO NO FIREWALL",
                    header_title=f"O endereço IP {rip} foi bloqueado!",
                    fields=[
                        ("🔒 Status no Firewall", "BLOQUEADO (Tráfego Cortado)", "#10b981"),
                        ("🌐 Endereço IP Bloqueado", rip, "#fbbf24"),
                        ("🏢 Organização", conn.security.destination_org, "#38bdf8"),
                    ],
                    explanation="Seu computador não enviará mais nenhum dado para este endereço IP.",
                    footer_tip="🔓 Para remover este bloqueio no futuro, acesse '🧱 Gerenciar Bloqueios (Firewall)'.",
                    status_type="success",
                )
            else:
                show_modern_status(
                    parent=self,
                    title="Não Foi Possível Bloquear o IP",
                    header_badge="🛡️ BLOQUEIO IMPEDIDO OU ERRO DE PERMISSÃO",
                    header_title=f"O endereço IP {rip} não pôde ser bloqueado",
                    fields=[
                        ("🌐 Endereço IP", rip, "#ef4444"),
                        ("ℹ️ Detalhes", result_msg, "#fbbf24"),
                    ],
                    explanation="Verifique a mensagem acima. Se for um roteador Wi-Fi local, o NetGuard impede o bloqueio para proteger sua internet.",
                    status_type="warning",
                )

    def _open_firewall_manager(self):
        FirewallManagerWindow(self)

    def _on_calculate_sha256(self):
        conn = self._require_selection("calcular o hash SHA-256")
        if not conn:
            return

        exe = conn.exe_path
        sha = compute_file_sha256(exe)
        self.clipboard_clear()
        self.clipboard_append(sha)

        show_modern_status(
            parent=self,
            title="Auditoria Criptográfica SHA-256",
            header_badge="🔑 HASH SHA-256 CALCULADO E COPIADO",
            header_title=f"Assinatura SHA-256 de '{conn.process_name}'",
            fields=[
                ("📦 Executável", conn.process_name, "#60a5fa"),
                ("📂 Caminho", exe, "#a1a1aa"),
                ("🔑 Hash SHA-256", sha, "#c084fc"),
            ],
            explanation="O código SHA-256 acima é a 'impressão digital' única deste arquivo executável e já foi copiado automaticamente para a sua Área de Transferência (Ctrl+V).",
            footer_tip="🔬 Dica para Estudantes: Cole este hash no site VirusTotal.com para verificar o arquivo em mais de 70 motores antivírus!",
            status_type="info",
        )

    def _on_open_folder(self):
        conn = self._require_selection("abrir a pasta do executável")
        if not conn:
            return
        success, msg = open_file_in_explorer(conn.exe_path)
        if success:
            self.selection_text.configure(
                text=f"📁 Pasta aberta no Explorer: {conn.process_name}",
                text_color="#10b981",
            )
        else:
            show_modern_status(
                parent=self,
                title="Caminho Inacessível",
                header_badge="⚠️ NÃO FOI POSSÍVEL ABRIR A PASTA",
                header_title="O executável não possui um caminho físico acessível",
                fields=[
                    ("📦 Processo", conn.process_name, "#60a5fa"),
                    ("📂 Caminho Registrado", conn.exe_path, "#fbbf24"),
                ],
                explanation=msg,
                status_type="warning",
            )

    def _on_copy_path(self):
        conn = self._require_selection("copiar o caminho")
        if not conn:
            return
        self.clipboard_clear()
        self.clipboard_append(conn.exe_path)
        self.selection_text.configure(
            text=f"✅ Caminho copiado para a Área de Transferência: {conn.exe_path}",
            text_color="#10b981",
        )

    def _on_copy_remote(self):
        conn = self._require_selection("copiar o IP remoto")
        if not conn:
            return
        remote_str = f"{conn.remote_ip}:{conn.remote_port}"
        self.clipboard_clear()
        self.clipboard_append(remote_str)
        self.selection_text.configure(
            text=f"✅ Endereço remoto copiado para a Área de Transferência: {remote_str}",
            text_color="#10b981",
        )

    def _on_copy_row(self):
        selected = self.tree.selection()
        if not selected:
            return
        vals = self.tree.item(selected[0], "values")
        row_str = " | ".join(str(v) for v in vals)
        self.clipboard_clear()
        self.clipboard_append(row_str)
        self.selection_text.configure(
            text="✅ Dados brutos da linha copiados para a Área de Transferência!",
            text_color="#10b981",
        )

    def _on_kill_process(self):
        conn = self._require_selection("encerrar o processo")
        if not conn:
            return

        pid = conn.pid
        proc_name = conn.process_name

        if not pid:
            show_modern_status(
                parent=self,
                title="Processo do Kernel Protegido",
                header_badge="🛡️ OPERAÇÃO NÃO PERMITIDA",
                header_title="Não é possível encerrar o Kernel do Sistema Operacional",
                fields=[("📦 Processo", proc_name, "#f59e0b")],
                explanation="Conexões sem PID ou pertencentes ao Kernel (PID 0/4) são gerenciadas diretamente pelo Windows.",
                status_type="warning",
            )
            return

        confirmed = ask_modern_confirmation(
            parent=self,
            title="Confirmar Encerramento de Processo",
            header_badge="⚠️ FINALIZAR TAREFA / ENCERRAR PROCESSO (KILL PID)",
            header_title=f"Deseja forçar o encerramento de '{proc_name}'?",
            fields=[
                ("📦 Programa", proc_name, "#f87171"),
                ("🔢 PID (Identificador)", str(pid), "#fbbf24"),
                ("📂 Caminho", conn.exe_path, "#a1a1aa"),
            ],
            explanation="O processo será fechado imediatamente e todas as suas conexões ativas serão cortadas.",
            footer_tip="⚠️ Atenção: Dados não salvos neste aplicativo poderão ser perdidos.",
            confirm_text="⚠️ Sim, Encerrar Agora",
            cancel_text="Cancelar",
            is_danger=True,
        )

        if confirmed:
            success, msg = terminate_process(pid)
            if success:
                show_modern_status(
                    parent=self,
                    title="Processo Encerrado",
                    header_badge="✅ PROCESSO FINALIZADO COM SUCESSO",
                    header_title=f"O processo '{proc_name}' (PID {pid}) foi encerrado!",
                    fields=[
                        ("📦 Processo", proc_name, "#10b981"),
                        ("🔢 PID Encerrado", str(pid), "#60a5fa"),
                    ],
                    explanation=msg,
                    status_type="success",
                )
                self.trigger_refresh(immediate=True)
            else:
                show_modern_status(
                    parent=self,
                    title="Erro ao Encerrar Processo",
                    header_badge="❌ NÃO FOI POSSÍVEL FINALIZAR O PROCESSO",
                    header_title=f"Falha ao encerrar '{proc_name}' (PID {pid})",
                    fields=[("⚠️ Erro", msg, "#ef4444")],
                    explanation="Processos protegidos do sistema ou de outros usuários exigem Modo Administrador.",
                    status_type="error",
                )

    # ---------------- Configurações ----------------

    def _handle_request_elevation(self):
        confirmed = ask_modern_confirmation(
            parent=self,
            title="Elevação de Privilégios (UAC)",
            header_badge="⚡ EXECUTAR COMO ADMINISTRADOR",
            header_title="Deseja reiniciar o NetGuard com acesso total de Administrador?",
            fields=[
                ("🛡️ Permissão Atual", "Usuário Padrão (Acesso Limitado)", "#f59e0b"),
                ("🔓 Permissão Após Elevar", "Administrador (Visão Total + Controle do Firewall)", "#10b981"),
            ],
            explanation=(
                "No modo Administrador, o NetGuard consegue identificar 100% dos executáveis do sistema "
                "e criar regras de bloqueio diretamente no Windows Defender Firewall."
            ),
            footer_tip="💡 O Windows exibirá a janela de confirmação de controle de conta (UAC).",
            confirm_text="⚡ Sim, Elevar Agora",
            cancel_text="Cancelar",
            is_danger=False,
        )
        if confirmed:
            if request_admin_elevation():
                self.destroy()
                sys.exit(0)
            else:
                show_modern_status(
                    parent=self,
                    title="Elevação Cancelada",
                    header_badge="⚠️ PERMISSÃO NÃO CONCEDIDA",
                    header_title="O aplicativo continuará no modo atual",
                    fields=[],
                    explanation="A solicitação de Administrador foi cancelada na janela do Windows.",
                    status_type="warning",
                )

    def _on_noise_switch_changed(self):
        self.hide_noise_enabled = bool(self.noise_switch.get())
        self.apply_filters()

    def _on_auto_switch_changed(self):
        self.auto_refresh_enabled = bool(self.auto_switch.get())
        if self.auto_refresh_enabled:
            self._schedule_next_refresh()
        elif self._scheduled_refresh_id:
            self.after_cancel(self._scheduled_refresh_id)
            self._scheduled_refresh_id = None

    def _on_interval_changed(self, choice: str):
        mapping = {"1s": 1000, "2s": 2000, "3s": 3000, "5s": 5000, "10s": 10000}
        self.refresh_interval_ms = mapping.get(choice, 3000)
        if self.auto_refresh_enabled:
            self._schedule_next_refresh()

    def _toggle_theme(self):
        current = ctk.get_appearance_mode()
        new_mode = "Light" if current == "Dark" else "Dark"
        ctk.set_appearance_mode(new_mode)
        self._configure_treeview_styles()

    def _show_about_author(self):
        self.clipboard_clear()
        self.clipboard_append("ronanzenatti@gmail.com")
        show_modern_status(
            parent=self,
            title="Sobre o NetGuard 2.0 — Créditos do Autor",
            header_badge="🛡️ NETGUARD 2.0 — CIBERSEGURANÇA & MONITORAMENTO DE REDE",
            header_title="Desenvolvido por Ronan Adriel Zenatti",
            fields=[
                ("👨‍💻 Desenvolvedor", "Ronan Adriel Zenatti", "#10b981"),
                ("✉️ E-mail de Contato", "ronanzenatti@gmail.com", "#38bdf8"),
                ("🐍 Tecnologias", "Python 3.12+  •  CustomTkinter  •  psutil  •  Windows Firewall API", "#c084fc"),
            ],
            explanation=(
                "Ferramenta criada para auxiliar tanto usuários leigos na proteção de sua privacidade e controle "
                "do Firewall quanto estudantes e entusiastas de Cibersegurança na inspeção técnica de sockets e processos."
            ),
            footer_tip="✅ O endereço de e-mail 'ronanzenatti@gmail.com' foi copiado para a sua Área de Transferência!",
            status_type="info",
        )

    def _export_csv(self):
        if not self.filtered_data:
            show_modern_status(
                parent=self,
                title="Sem Dados",
                header_badge="⚠️ TABELA VAZIA",
                header_title="Não há conexões filtradas para exportar",
                fields=[],
                explanation="Ajuste os filtros de busca antes de exportar para CSV.",
                status_type="warning",
            )
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("Arquivos CSV", "*.csv"), ("Todos os Arquivos", "*.*")],
            title="Exportar Auditoria de Conexões (CSV)",
            initialfile=f"netguard_cybersec_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        )
        if not file_path:
            return

        try:
            with open(file_path, mode="w", newline="", encoding="utf-8-sig") as csv_file:
                fieldnames = [
                    "risk_badge",
                    "pid",
                    "process_name",
                    "proto",
                    "local_ip",
                    "local_port",
                    "remote_ip",
                    "remote_port",
                    "destination_org",
                    "status",
                    "username",
                    "exe_path",
                ]
                writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
                writer.writeheader()
                for conn in self.filtered_data:
                    writer.writerow(conn.to_dict())

            show_modern_status(
                parent=self,
                title="Exportação Concluída",
                header_badge="📥 RELATÓRIO CSV EXPORTADO COM SUCESSO",
                header_title="Todas as conexões listadas foram salvas!",
                fields=[
                    ("📄 Total Exportado", f"{len(self.filtered_data)} conexões", "#10b981"),
                    ("📂 Arquivo Salvo", file_path, "#60a5fa"),
                ],
                explanation="Você pode abrir este arquivo no Microsoft Excel, Google Sheets ou ferramentas de análise de dados.",
                status_type="success",
            )
        except Exception as e:
            show_modern_status(
                parent=self,
                title="Erro ao Exportar",
                header_badge="❌ FALHA AO SALVAR ARQUIVO CSV",
                header_title="Não foi possível gravar o arquivo no local escolhido",
                fields=[("⚠️ Erro", str(e), "#ef4444")],
                explanation="Verifique se o arquivo não está aberto em outro programa.",
                status_type="error",
            )


def main():
    app = NetGuardApp()
    app.mainloop()


if __name__ == "__main__":
    main()
