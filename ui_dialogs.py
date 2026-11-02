"""
NetGuard 2.0 — Componentes Visuais Modernos (Diálogos, Alertas e Menu de Contexto)
Substitui as janelas antigas do Windows (tk.messagebox e tk.Menu) por janelas
CustomTkinter escuras, com cores semânticas, textos em negrito e cartões estruturados.
"""

from __future__ import annotations

from typing import Callable, List, Optional, Tuple
import customtkinter as ctk


# Paleta semântica de cores modernas
COLOR_BG_MAIN = ("#f8fafc", "#141418")
COLOR_BG_CARD = ("#ffffff", "#1e1e26")
COLOR_BG_SUBCARD = ("#f1f5f9", "#272732")
COLOR_BORDER = ("#cbd5e1", "#343442")

COLOR_SUCCESS = "#10b981"      # Verde Esmeralda
COLOR_SUCCESS_BG = "#064e3b"
COLOR_WARNING = "#f59e0b"      # Âmbar / Laranja
COLOR_WARNING_BG = "#451a03"
COLOR_DANGER = "#ef4444"       # Vermelho Alerta
COLOR_DANGER_BG = "#450a0a"
COLOR_INFO = "#3b82f6"         # Azul Moderno
COLOR_INFO_BG = "#172554"
COLOR_CYBER = "#a855f7"        # Roxo Cybersec


def _center_toplevel(win: ctk.CTkToplevel, parent: ctk.CTk, width: int, height: int):
    """Centraliza uma janela CTkToplevel exatamente sobre a janela principal."""
    win.update_idletasks()
    try:
        px = parent.winfo_rootx()
        py = parent.winfo_rooty()
        pw = parent.winfo_width()
        ph = parent.winfo_height()
        x = px + max(0, (pw - width) // 2)
        y = py + max(0, (ph - height) // 2)
    except Exception:
        x, y = 300, 200
    win.geometry(f"{width}x{height}+{x}+{y}")


class ModernModalDialog(ctk.CTkToplevel):
    """
    Janela de diálogo moderna com cabeçalho colorido, campos chave-valor em negrito,
    caixa de destaque explicativa e botões de ação grandes e claros.
    """

    def __init__(
        self,
        parent: ctk.CTk,
        title: str,
        header_badge: str,
        header_title: str,
        accent_color: str,
        badge_bg_color: str,
        fields: List[Tuple[str, str, Optional[str]]],
        explanation: str,
        footer_tip: str = "",
        confirm_text: str = "Confirmar",
        cancel_text: Optional[str] = None,
        confirm_fg: Optional[str] = None,
        confirm_hover: Optional[str] = None,
        width: int = 560,
    ):
        super().__init__(parent)
        self.result: bool = False

        self.title(title)
        self.configure(fg_color=COLOR_BG_MAIN)
        self.resizable(False, False)
        self.transient(parent)
        self.attributes("-topmost", True)

        # Cálculo dinâmico da altura baseado na quantidade de informações
        base_height = 270 + (len(fields) * 34) + (45 if footer_tip else 0)
        height = max(340, min(560, base_height))
        _center_toplevel(self, parent, width, height)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # ---------------- 1. Barra Superior de Destaque ----------------
        top_bar = ctk.CTkFrame(
            self,
            corner_radius=0,
            fg_color=badge_bg_color,
            border_width=0,
        )
        top_bar.grid(row=0, column=0, sticky="ew")
        top_bar.grid_columnconfigure(0, weight=1)

        badge_lbl = ctk.CTkLabel(
            top_bar,
            text=header_badge.upper(),
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=accent_color,
            anchor="w",
        )
        badge_lbl.grid(row=0, column=0, padx=20, pady=(12, 0), sticky="w")

        title_lbl = ctk.CTkLabel(
            top_bar,
            text=header_title,
            font=ctk.CTkFont(size=17, weight="bold"),
            text_color="#ffffff",
            anchor="w",
            wraplength=width - 40,
            justify="left",
        )
        title_lbl.grid(row=1, column=0, padx=20, pady=(2, 12), sticky="w")

        # ---------------- 2. Corpo Estruturado ----------------
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.grid(row=1, column=0, sticky="nsew", padx=20, pady=14)
        body.grid_columnconfigure(0, weight=1)

        current_row = 0

        # Cartão de Campos (Chave em Negrito + Valor Colorido em Negrito)
        if fields:
            fields_card = ctk.CTkFrame(
                body,
                corner_radius=8,
                fg_color=COLOR_BG_CARD,
                border_width=1,
                border_color=COLOR_BORDER,
            )
            fields_card.grid(row=current_row, column=0, sticky="ew", pady=(0, 12))
            fields_card.grid_columnconfigure(1, weight=1)
            current_row += 1

            for idx, (label_text, val_text, val_color) in enumerate(fields):
                pad_y = (10, 4) if idx == 0 else ((4, 10) if idx == len(fields) - 1 else (4, 4))

                lbl_k = ctk.CTkLabel(
                    fields_card,
                    text=f"{label_text}:",
                    font=ctk.CTkFont(size=12, weight="bold"),
                    text_color=("gray30", "#a1a1aa"),
                    anchor="w",
                )
                lbl_k.grid(row=idx, column=0, padx=(14, 8), pady=pad_y, sticky="nw")

                lbl_v = ctk.CTkLabel(
                    fields_card,
                    text=str(val_text),
                    font=ctk.CTkFont(size=12, weight="bold"),
                    text_color=val_color or ("gray10", "#f4f4f5"),
                    anchor="w",
                    justify="left",
                    wraplength=width - 180,
                )
                lbl_v.grid(row=idx, column=1, padx=(0, 14), pady=pad_y, sticky="nw")

        # Texto Explicativo Principal
        if explanation:
            exp_lbl = ctk.CTkLabel(
                body,
                text=explanation,
                font=ctk.CTkFont(size=13),
                text_color=("gray15", "#e4e4e7"),
                justify="left",
                anchor="w",
                wraplength=width - 44,
            )
            exp_lbl.grid(row=current_row, column=0, sticky="ew", pady=(0, 10))
            current_row += 1

        # Caixa de Dica / Aviso em Negrito
        if footer_tip:
            tip_box = ctk.CTkFrame(
                body,
                corner_radius=6,
                fg_color=COLOR_BG_SUBCARD,
                border_width=1,
                border_color=accent_color,
            )
            tip_box.grid(row=current_row, column=0, sticky="ew", pady=(2, 4))

            tip_lbl = ctk.CTkLabel(
                tip_box,
                text=footer_tip,
                font=ctk.CTkFont(size=12, weight="bold"),
                text_color=accent_color,
                justify="left",
                anchor="w",
                wraplength=width - 68,
            )
            tip_lbl.pack(fill="x", padx=12, pady=8)

        # ---------------- 3. Rodapé com Botões ----------------
        btn_frame = ctk.CTkFrame(self, fg_color=("gray90", "#18181f"), corner_radius=0)
        btn_frame.grid(row=2, column=0, sticky="ew")

        if cancel_text:
            cancel_btn = ctk.CTkButton(
                btn_frame,
                text=cancel_text,
                width=120,
                height=36,
                font=ctk.CTkFont(size=13, weight="bold"),
                fg_color=("gray75", "#272732"),
                hover_color=("gray65", "#3f3f4e"),
                text_color=("gray10", "#f4f4f5"),
                command=self._on_cancel,
            )
            cancel_btn.pack(side="right", padx=(8, 20), pady=12)

        c_fg = confirm_fg or accent_color
        c_hover = confirm_hover or accent_color

        confirm_btn = ctk.CTkButton(
            btn_frame,
            text=confirm_text,
            width=190 if cancel_text else 150,
            height=36,
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color=c_fg,
            hover_color=c_hover,
            text_color="#ffffff",
            command=self._on_confirm,
        )
        confirm_btn.pack(side="right", padx=(20, 4 if cancel_text else 20), pady=12)

        self.bind("<Escape>", lambda e: self._on_cancel())
        self.bind("<Return>", lambda e: self._on_confirm())

        self.lift()
        self.focus_force()
        self.grab_set()

    def _on_confirm(self):
        self.result = True
        self.grab_release()
        self.destroy()

    def _on_cancel(self):
        self.result = False
        self.grab_release()
        self.destroy()


def ask_modern_confirmation(
    parent: ctk.CTk,
    title: str,
    header_badge: str,
    header_title: str,
    fields: List[Tuple[str, str, Optional[str]]],
    explanation: str,
    footer_tip: str = "",
    confirm_text: str = "Confirmar",
    cancel_text: str = "Cancelar",
    is_danger: bool = True,
) -> bool:
    """Exibe uma janela modal de confirmação moderna e retorna True se o usuário confirmar."""
    accent = COLOR_DANGER if is_danger else COLOR_WARNING
    bg = COLOR_DANGER_BG if is_danger else COLOR_WARNING_BG
    hover = "#b91c1c" if is_danger else "#b45309"

    dlg = ModernModalDialog(
        parent=parent,
        title=title,
        header_badge=header_badge,
        header_title=header_title,
        accent_color=accent,
        badge_bg_color=bg,
        fields=fields,
        explanation=explanation,
        footer_tip=footer_tip,
        confirm_text=confirm_text,
        cancel_text=cancel_text,
        confirm_fg=accent,
        confirm_hover=hover,
    )
    parent.wait_window(dlg)
    return dlg.result


def show_modern_status(
    parent: ctk.CTk,
    title: str,
    header_badge: str,
    header_title: str,
    fields: List[Tuple[str, str, Optional[str]]],
    explanation: str,
    footer_tip: str = "",
    status_type: str = "success",  # "success", "warning", "error", "info"
):
    """Exibe uma janela de resultado (Sucesso, Aviso, Erro ou Info) rica em cores e negrito."""
    if status_type == "success":
        accent, bg, hover = COLOR_SUCCESS, COLOR_SUCCESS_BG, "#047857"
    elif status_type == "warning":
        accent, bg, hover = COLOR_WARNING, COLOR_WARNING_BG, "#b45309"
    elif status_type == "error":
        accent, bg, hover = COLOR_DANGER, COLOR_DANGER_BG, "#b91c1c"
    else:
        accent, bg, hover = COLOR_INFO, COLOR_INFO_BG, "#1d4ed8"

    dlg = ModernModalDialog(
        parent=parent,
        title=title,
        header_badge=header_badge,
        header_title=header_title,
        accent_color=accent,
        badge_bg_color=bg,
        fields=fields,
        explanation=explanation,
        footer_tip=footer_tip,
        confirm_text="✅ Entendido",
        cancel_text=None,
        confirm_fg=accent,
        confirm_hover=hover,
    )
    parent.wait_window(dlg)


class ModernContextMenu(ctk.CTkToplevel):
    """
    Menu de contexto (botão direito) customizado no estilo Dark do CustomTkinter,
    com cabeçalho identificando o processo selecionado, ícones, cores semânticas e negrito.
    Usa agendamento assíncrono na thread principal para abrir janelas modais com 100% de confiabilidade.
    """

    def __init__(
        self,
        parent: ctk.CTk,
        x: int,
        y: int,
        process_title: str,
        risk_badge: str,
        items: List[Optional[Tuple[str, Callable, Optional[str], Optional[str], bool]]],
    ):
        super().__init__(parent)
        self.master_parent = parent
        self._invoked = False

        self.overrideredirect(True)
        self.attributes("-topmost", True)
        self.configure(fg_color="#18181f")

        # Container com borda elegante
        container = ctk.CTkFrame(
            self,
            corner_radius=8,
            fg_color="#18181f",
            border_width=1,
            border_color="#3f3f50",
        )
        container.pack(fill="both", expand=True, padx=1, pady=1)

        # Cabeçalho do Menu mostrando qual processo foi clicado
        header = ctk.CTkFrame(container, corner_radius=6, fg_color="#23232e")
        header.pack(fill="x", padx=5, pady=(5, 4))

        ctk.CTkLabel(
            header,
            text=f"⚡ {process_title}",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#60a5fa",
            anchor="w",
        ).pack(fill="x", padx=10, pady=(5, 0))

        ctk.CTkLabel(
            header,
            text=risk_badge,
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="#a1a1aa",
            anchor="w",
        ).pack(fill="x", padx=10, pady=(0, 5))

        # Lista de Opções
        for entry in items:
            if entry is None:
                sep = ctk.CTkFrame(container, height=1, fg_color="#2e2e3a")
                sep.pack(fill="x", padx=8, pady=3)
                continue

            label, callback, text_color, hover_color, is_bold = entry
            btn = ctk.CTkButton(
                container,
                text=f"  {label}",
                anchor="w",
                height=32,
                width=280,
                corner_radius=5,
                fg_color="transparent",
                hover_color=hover_color or "#2b2b38",
                text_color=text_color or "#f4f4f5",
                font=ctk.CTkFont(size=12, weight="bold" if is_bold else "normal"),
                command=lambda cb=callback: self._invoke(cb),
            )
            btn.pack(fill="x", padx=5, pady=1)

        self.update_idletasks()
        w = self.winfo_reqwidth()
        h = self.winfo_reqheight()

        # Ajustar para não sair da borda da tela
        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()
        pos_x = min(x, screen_w - w - 10)
        pos_y = min(y, screen_h - h - 40)

        self.geometry(f"{w}x{h}+{pos_x}+{pos_y}")
        self.lift()

        self.bind("<Escape>", lambda e: self.close_menu())

    def is_point_inside(self, root_x: int, root_y: int) -> bool:
        """Verifica se uma coordenada de tela (x, y) está dentro do menu."""
        if not self.winfo_exists():
            return False
        mx = self.winfo_rootx()
        my = self.winfo_rooty()
        mw = self.winfo_width()
        mh = self.winfo_height()
        return (mx <= root_x <= mx + mw) and (my <= root_y <= my + mh)

    def close_menu(self):
        if self.winfo_exists():
            self.destroy()

    def _invoke(self, callback: Callable):
        if self._invoked:
            return
        self._invoked = True
        parent = self.master_parent
        self.close_menu()
        # Agendar a execução na janela principal após o fechamento completo do menu
        parent.after(30, callback)
