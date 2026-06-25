# -*- coding: utf-8 -*-
import os
import sys
import time
import threading
import traceback
from tkinter import filedialog, messagebox, Text as TkText

import customtkinter as ctk

from sm4_engine import key_expansion, sm4_encrypt_block, sm4_decrypt_block
from file_crypto import encrypt_file, decrypt_file


COLOR_BG_WINDOW = "#F2F2F2"
COLOR_CARD      = "#FFFFFF"
COLOR_BORDER    = "#000000"
COLOR_ACCENT    = "#0000FF"      # 主色：纯蓝
COLOR_ACCENT_DARK = "#0000CC"    # 深蓝
COLOR_YELLOW    = "#DAFC08"      # 高亮色：霓虹黄
COLOR_TEXT      = "#000000"
COLOR_TEXT_MUTED = "#666666"
COLOR_LOG_BG    = "#FFFFFF"
COLOR_LOG_TEXT  = "#000000"
COLOR_LOG_ACCENT = "#0000FF"

FONT_FAMILY  = "Consolas"
FONT_HERO    = (FONT_FAMILY, 36, "bold")
FONT_HERO_LABEL = (FONT_FAMILY, 12, "bold")
FONT_H1      = (FONT_FAMILY, 13, "bold")
FONT_BODY    = (FONT_FAMILY, 11)
FONT_BUTTON  = (FONT_FAMILY, 12, "bold")
FONT_LOG     = (FONT_FAMILY, 11)
FONT_STATUS  = (FONT_FAMILY, 10)
FONT_SMALL   = (FONT_FAMILY, 9)

BORDER_WEIGHT = 3
SHADOW_OFFSET = 5
CARD_RADIUS = 14      
BTN_RADIUS  = 12      

DEFAULT_KEY = bytes.fromhex("0123456789abcdeffedcba9876543210")


# ============================================================
# CustomTkinter 设置
# ============================================================
ctk.set_appearance_mode("light")
ctk.set_default_color_theme("blue")


# ============================================================
# 组件库 
# ============================================================

class BrutalShadowCard(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color=COLOR_BORDER,
                         corner_radius=CARD_RADIUS, border_width=0)
        self.card = ctk.CTkFrame(
            self,
            fg_color=COLOR_CARD,
            border_color=COLOR_BORDER,
            border_width=BORDER_WEIGHT,
            corner_radius=CARD_RADIUS,
        )
        self.card.pack(fill="both", expand=True,
                       padx=(0, SHADOW_OFFSET), pady=(0, SHADOW_OFFSET))


class BrutalCard(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(
            master,
            fg_color=COLOR_CARD,
            border_color=COLOR_BORDER,
            border_width=BORDER_WEIGHT,
            corner_radius=CARD_RADIUS,
            **kwargs,
        )


class BrutalButton(ctk.CTkButton):
    def __init__(self, master, text, command=None, accent=False, highlight=False, **kwargs):
        height = kwargs.pop("height", 40)
        width = kwargs.pop("width", None)

        if highlight:
            fg = COLOR_YELLOW
            hover = "#FFFF99"
            tc = COLOR_BORDER
        elif accent:
            fg = COLOR_ACCENT
            hover = COLOR_ACCENT_DARK
            tc = "white"
        else:
            fg = COLOR_CARD
            hover = "#EEEEEE"
            tc = COLOR_TEXT

        super().__init__(
            master, text=text, command=command,
            fg_color=fg, text_color=tc,
            text_color_disabled=COLOR_TEXT_MUTED,
            hover_color=hover,
            border_color=COLOR_BORDER,
            border_width=BORDER_WEIGHT,
            corner_radius=BTN_RADIUS,
            font=FONT_BUTTON,
            height=height,
            width=width if width else 0,
            **kwargs,
        )


class BrutalEntry(ctk.CTkEntry):
    def __init__(self, master, **kwargs):
        super().__init__(
            master,
            fg_color=COLOR_CARD,
            border_color=COLOR_BORDER,
            border_width=BORDER_WEIGHT,
            corner_radius=BTN_RADIUS,
            text_color=COLOR_TEXT,
            placeholder_text_color=COLOR_TEXT_MUTED,
            font=FONT_BODY,
            height=42,
            **kwargs,
        )
        self.bind("<FocusIn>", lambda e: self.configure(border_color=COLOR_ACCENT))
        self.bind("<FocusOut>", lambda e: self.configure(border_color=COLOR_BORDER))


class BrutalProgressBar(ctk.CTkFrame):
    def __init__(self, master, height=28, **kwargs):
        super().__init__(
            master,
            fg_color=COLOR_CARD,
            border_color=COLOR_BORDER,
            border_width=BORDER_WEIGHT,
            corner_radius=BTN_RADIUS,
            height=height,
        )
        self._value = 0.0
        self._bar = ctk.CTkProgressBar(
            self,
            fg_color=COLOR_CARD,
            progress_color=COLOR_ACCENT,
            border_width=0,
            corner_radius=max(0, BTN_RADIUS - 3),
        )
        self._bar.pack(fill="both", expand=True,
                       padx=BORDER_WEIGHT + 2, pady=BORDER_WEIGHT + 2)
        self._bar.set(0.0)

    def set(self, value):
        value = max(0.0, min(1.0, value))
        self._value = value
        self._bar.set(value)


# ============================================================
# 主应用
# ============================================================

class Sm4CryptoApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("SM4 // NEO-BRUTAL")
        self.geometry("1000x700")
        self.minsize(900, 640)
        self.configure(fg_color=COLOR_BG_WINDOW)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # ========== HERO 标题区 ==========
        self.header_wrap = BrutalShadowCard(self)
        self.header_wrap.grid(row=0, column=0, padx=16, pady=(16, 0), sticky="nsew")
        header = self.header_wrap.card
        header.grid_columnconfigure(0, weight=1)

        # 蓝色大色块
        hero_area = ctk.CTkFrame(header, fg_color=COLOR_ACCENT, corner_radius=10)
        hero_area.grid(row=0, column=0, padx=12, pady=(12, 6), sticky="ew")
        hero_area.grid_columnconfigure(0, weight=1)

        # 标题
        ctk.CTkLabel(
            hero_area,
            text="SM4-FileCrypto",
            font=FONT_HERO,
            text_color="white",
        ).grid(row=0, column=0, padx=20, pady=(10, 2), sticky="w")

        ctk.CTkLabel(
            hero_area,
            text="@ 2024302181018 & 2024302181053",
            font=FONT_HERO_LABEL,
            text_color=COLOR_YELLOW,
        ).grid(row=1, column=0, padx=20, pady=(0, 10), sticky="w")

        # 分隔线 + 标签说明
        sep = ctk.CTkFrame(header, fg_color=COLOR_BORDER, height=3, corner_radius=0)
        sep.grid(row=1, column=0, padx=16, pady=(4, 0), sticky="ew")

        ctk.CTkLabel(
            header,
            text="  CBC + CTS   ·   SM4   ·   BINARY-SAFE   ·   FAST  ",
            font=(FONT_FAMILY, 10, "bold"),
            text_color=COLOR_TEXT,
        ).grid(row=2, column=0, padx=12, pady=(6, 10), sticky="w")

        # ========== Tabview ==========
        self.tabview = ctk.CTkTabview(
            self,
            corner_radius=CARD_RADIUS,
            fg_color=COLOR_BG_WINDOW,
            border_width=0,
            segmented_button_fg_color=COLOR_CARD,
            segmented_button_selected_color=COLOR_ACCENT,
            segmented_button_selected_hover_color=COLOR_ACCENT_DARK,
            segmented_button_unselected_color=COLOR_CARD,
            text_color=COLOR_TEXT,
            text_color_disabled=COLOR_TEXT_MUTED,
        )
        self.tabview.grid(row=1, column=0, padx=16, pady=10, sticky="nsew")
        self.tabview.add(" ENCRYPT // 加密 ")
        self.tabview.add(" DECRYPT // 解密 ")
        self.tabview.grid_columnconfigure(0, weight=1)

        for tab_name in (" ENCRYPT // 加密 ", " DECRYPT // 解密 "):
            self.tabview.tab(tab_name).configure(fg_color=COLOR_BG_WINDOW)

        self._build_encrypt_tab(self.tabview.tab(" ENCRYPT // 加密 "))
        self._build_decrypt_tab(self.tabview.tab(" DECRYPT // 解密 "))

        # Tab 选中态：白字
        def refresh_tab_colors():
            current = self.tabview.get()
            if hasattr(self.tabview, "_segmented_button"):
                sb = self.tabview._segmented_button
                if hasattr(sb, "_buttons_dict"):
                    for name, btn in sb._buttons_dict.items():
                        try:
                            if name == current:
                                btn.configure(text_color="white")
                            else:
                                btn.configure(text_color=COLOR_TEXT)
                        except Exception:
                            pass

        refresh_tab_colors()

        if hasattr(self.tabview, "_segmented_button"):
            original_cmd = self.tabview._segmented_button.cget("command")
            def combined_cmd(value):
                refresh_tab_colors()
                if original_cmd is not None:
                    try:
                        original_cmd(value)
                    except Exception:
                        pass
            self.tabview._segmented_button.configure(command=combined_cmd)

        # ========== 底部状态栏 ==========
        self.status_var = ctk.StringVar(value="// READY")
        self.status_wrap = BrutalShadowCard(self)
        self.status_wrap.grid(row=2, column=0, padx=16, pady=(0, 16), sticky="ew")

        status_bar = self.status_wrap.card
        status_bar.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            status_bar,
            textvariable=self.status_var,
            anchor="w",
            text_color=COLOR_TEXT,
            font=FONT_STATUS,
        ).grid(row=0, column=0, padx=12, pady=6, sticky="w")

        ctk.CTkLabel(
            status_bar,
            text="[ v1.0 // 2026 ]",
            anchor="e",
            text_color=COLOR_ACCENT,
            font=FONT_STATUS,
        ).grid(row=0, column=1, padx=18, pady=10, sticky="e")

    # ===== 通用 UI 工具 =====
    def _label(self, parent, text):
        return ctk.CTkLabel(parent, text=text, font=FONT_H1, text_color=COLOR_TEXT, anchor="w")

    def _set_status(self, text):
        self.status_var.set(text)

    def _browse_file(self, var, save=False):
        if save:
            path = filedialog.asksaveasfilename()
        else:
            path = filedialog.askopenfilename()
        if path:
            var.set(path)

    def _toggle_password(self, entry):
        current = entry.cget("show")
        entry.configure(show="" if current else "*")

    def _append_log(self, textbox, msg, color=None):
        textbox.configure(state="normal")
        if color:
            tag = f"color_{color.replace('#', '')}"
            textbox.tag_configure(tag, foreground=color)
            textbox.insert("end", msg + "\n", tag)
        else:
            textbox.insert("end", msg + "\n")
        textbox.see("end")
        textbox.configure(state="disabled")

    def _parse_key(self, hex_str):
        key = bytes.fromhex(hex_str.strip())
        if len(key) != 16:
            raise ValueError(f"key must be 16 bytes, got {len(key)}")
        return key

    def _build_encrypt_tab(self, parent):
        parent.grid_columnconfigure(0, weight=1)

        self.enc_input_var = ctk.StringVar()
        self.enc_output_var = ctk.StringVar()
        self.enc_key_var = ctk.StringVar(value=DEFAULT_KEY.hex())

        # 表单卡片
        form_wrap = BrutalShadowCard(parent)
        form_wrap.grid(row=0, column=0, padx=4, pady=(4, 4), sticky="ew")
        form = form_wrap.card
        form.grid_columnconfigure(0, weight=1)
        form_frame = ctk.CTkFrame(form, fg_color=COLOR_CARD)
        form_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        form_frame.grid_columnconfigure(0, weight=1)

        # --- 输入文件 ---
        self._label(form_frame, "> INPUT FILE // 选择要加密的文件").grid(
            row=0, column=0, padx=4, pady=(2, 3), sticky="w")
        f1 = ctk.CTkFrame(form_frame, fg_color=COLOR_CARD)
        f1.grid(row=1, column=0, padx=4, pady=(0, 8), sticky="ew")
        f1.grid_columnconfigure(0, weight=1)
        BrutalEntry(f1, textvariable=self.enc_input_var,
                    placeholder_text="... click BROWSE to select a file").grid(row=0, column=0, sticky="ew")
        BrutalButton(f1, text="[ BROWSE ]", accent=True,
                     width=140, height=42,
                     command=lambda: self._browse_file(self.enc_input_var, save=False)
                     ).grid(row=0, column=1, padx=(10, 0))

        # --- 输出文件 ---
        self._label(form_frame, "> OUTPUT FILE // 输出文件").grid(
            row=2, column=0, padx=4, pady=(0, 3), sticky="w")
        f2 = ctk.CTkFrame(form_frame, fg_color=COLOR_CARD)
        f2.grid(row=3, column=0, padx=4, pady=(0, 8), sticky="ew")
        f2.grid_columnconfigure(0, weight=1)
        BrutalEntry(f2, textvariable=self.enc_output_var,
                    placeholder_text="... leave empty to auto-add .sm4").grid(row=0, column=0, sticky="ew")
        BrutalButton(f2, text="[ SAVE AS ]",
                     width=140, height=42,
                     command=lambda: self._browse_file(self.enc_output_var, save=True)
                     ).grid(row=0, column=1, padx=(10, 0))

        # --- 密钥 ---
        self._label(form_frame, "> KEY // 密钥").grid(
            row=4, column=0, padx=4, pady=(0, 3), sticky="w")
        f3 = ctk.CTkFrame(form_frame, fg_color=COLOR_CARD)
        f3.grid(row=5, column=0, padx=4, pady=(0, 6), sticky="ew")
        f3.grid_columnconfigure(0, weight=1)
        self.enc_key_entry = BrutalEntry(f3, textvariable=self.enc_key_var, show="*")
        self.enc_key_entry.grid(row=0, column=0, sticky="ew")
        BrutalButton(f3, text="[ SHOW ]",
                     width=120, height=42,
                     command=lambda: self._toggle_password(self.enc_key_entry)
                     ).grid(row=0, column=1, padx=(10, 0))

        # --- 主操作按钮 ---
        btn_wrap = BrutalShadowCard(parent)
        btn_wrap.grid(row=1, column=0, padx=4, pady=(8, 4), sticky="ew")
        btn_wrap.card.grid_columnconfigure(0, weight=1)
        BrutalButton(
            btn_wrap.card,
            text="▶ START ENCRYPTION // 开始加密",
            accent=True, height=46,
            command=self._do_encrypt,
        ).grid(row=0, column=0, padx=0, pady=0, sticky="ew")

        # --- 进度条 ---
        self._label(parent, "> PROGRESS // 进度").grid(
            row=2, column=0, padx=6, pady=(6, 3), sticky="w")
        self.enc_progress = BrutalProgressBar(parent, height=28)
        self.enc_progress.grid(row=3, column=0, padx=4, pady=2, sticky="ew")

        # --- 日志区 ---
        self._label(parent, "> ACTIVITY // 操作日志").grid(
            row=4, column=0, padx=6, pady=(6, 3), sticky="w")
        log_wrap = BrutalShadowCard(parent)
        log_wrap.grid(row=5, column=0, padx=4, pady=(0, 8), sticky="nsew")
        log_inner = log_wrap.card
        log_inner.grid_columnconfigure(0, weight=1)
        log_inner.grid_rowconfigure(0, weight=1)

        self.enc_log = TkText(
            log_inner,
            bg=COLOR_LOG_BG,
            fg=COLOR_LOG_TEXT,
            insertbackground=COLOR_BORDER,
            selectbackground=COLOR_ACCENT,
            selectforeground="white",
            bd=0,
            highlightthickness=0,
            font=FONT_LOG,
            wrap="word",
            height=6,
        )
        self.enc_log.grid(row=0, column=0, padx=6, pady=6, sticky="nsew")
        self.enc_log.insert("end", "// SM4 CRYPTO SYSTEM v1.0\n")
        self.enc_log.insert("end", "// awaiting input...\n")
        self.enc_log.configure(state="disabled")

        parent.grid_rowconfigure(5, weight=1)

    # ===== 解密 Tab =====
    def _build_decrypt_tab(self, parent):
        parent.grid_columnconfigure(0, weight=1)

        self.dec_input_var = ctk.StringVar()
        self.dec_output_var = ctk.StringVar()
        self.dec_key_var = ctk.StringVar(value=DEFAULT_KEY.hex())

        # 表单卡片
        form_wrap = BrutalShadowCard(parent)
        form_wrap.grid(row=0, column=0, padx=4, pady=(4, 4), sticky="ew")
        form = form_wrap.card
        form.grid_columnconfigure(0, weight=1)
        form_frame = ctk.CTkFrame(form, fg_color=COLOR_CARD)
        form_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        form_frame.grid_columnconfigure(0, weight=1)

        # --- 输入文件 ---
        self._label(form_frame, "> INPUT FILE // 选择要解密的文件 (.sm4)").grid(
            row=0, column=0, padx=4, pady=(2, 3), sticky="w")
        f1 = ctk.CTkFrame(form_frame, fg_color=COLOR_CARD)
        f1.grid(row=1, column=0, padx=4, pady=(0, 8), sticky="ew")
        f1.grid_columnconfigure(0, weight=1)
        BrutalEntry(f1, textvariable=self.dec_input_var,
                    placeholder_text="... click BROWSE to select a file").grid(row=0, column=0, sticky="ew")
        BrutalButton(f1, text="[ BROWSE ]", accent=True,
                     width=140, height=42,
                     command=lambda: self._browse_file(self.dec_input_var, save=False)
                     ).grid(row=0, column=1, padx=(10, 0))

        # --- 输出文件 ---
        self._label(form_frame, "> OUTPUT FILE // 输出文件").grid(
            row=2, column=0, padx=4, pady=(0, 3), sticky="w")
        f2 = ctk.CTkFrame(form_frame, fg_color=COLOR_CARD)
        f2.grid(row=3, column=0, padx=4, pady=(0, 8), sticky="ew")
        f2.grid_columnconfigure(0, weight=1)
        BrutalEntry(f2, textvariable=self.dec_output_var,
                    placeholder_text="... leave empty to auto-generate").grid(row=0, column=0, sticky="ew")
        BrutalButton(f2, text="[ SAVE AS ]",
                     width=140, height=42,
                     command=lambda: self._browse_file(self.dec_output_var, save=True)
                     ).grid(row=0, column=1, padx=(10, 0))

        # --- 密钥 ---
        self._label(form_frame, "> KEY // 密钥").grid(
            row=4, column=0, padx=4, pady=(0, 3), sticky="w")
        f3 = ctk.CTkFrame(form_frame, fg_color=COLOR_CARD)
        f3.grid(row=5, column=0, padx=4, pady=(0, 6), sticky="ew")
        f3.grid_columnconfigure(0, weight=1)
        self.dec_key_entry = BrutalEntry(f3, textvariable=self.dec_key_var, show="*")
        self.dec_key_entry.grid(row=0, column=0, sticky="ew")
        BrutalButton(f3, text="[ SHOW ]",
                     width=120, height=42,
                     command=lambda: self._toggle_password(self.dec_key_entry)
                     ).grid(row=0, column=1, padx=(10, 0))

        # --- 主操作按钮 ---
        btn_wrap = BrutalShadowCard(parent)
        btn_wrap.grid(row=1, column=0, padx=4, pady=(8, 4), sticky="ew")
        btn_wrap.card.grid_columnconfigure(0, weight=1)
        BrutalButton(
            btn_wrap.card,
            text="▶ START DECRYPTION // 开始解密",
            accent=True, height=46,
            command=self._do_decrypt,
        ).grid(row=0, column=0, padx=0, pady=0, sticky="ew")

        # --- 进度条 ---
        self._label(parent, "> PROGRESS // 进度").grid(
            row=2, column=0, padx=6, pady=(6, 3), sticky="w")
        self.dec_progress = BrutalProgressBar(parent, height=28)
        self.dec_progress.grid(row=3, column=0, padx=4, pady=2, sticky="ew")

        # --- 日志区 ---
        self._label(parent, "> ACTIVITY // 操作日志").grid(
            row=4, column=0, padx=6, pady=(6, 3), sticky="w")
        log_wrap = BrutalShadowCard(parent)
        log_wrap.grid(row=5, column=0, padx=4, pady=(0, 8), sticky="nsew")
        log_inner = log_wrap.card
        log_inner.grid_columnconfigure(0, weight=1)
        log_inner.grid_rowconfigure(0, weight=1)

        self.dec_log = TkText(
            log_inner,
            bg=COLOR_LOG_BG,
            fg=COLOR_LOG_TEXT,
            insertbackground=COLOR_BORDER,
            selectbackground=COLOR_ACCENT,
            selectforeground="white",
            bd=0,
            highlightthickness=0,
            font=FONT_LOG,
            wrap="word",
            height=6,
        )
        self.dec_log.grid(row=0, column=0, padx=6, pady=6, sticky="nsew")
        self.dec_log.insert("end", "// SM4FileCrypto v1.0\n")
        self.dec_log.insert("end", "// awaiting input...\n")
        self.dec_log.configure(state="disabled")

        parent.grid_rowconfigure(5, weight=1)

    def _do_encrypt(self):
        in_path = self.enc_input_var.get().strip()
        if not in_path or not os.path.isfile(in_path):
            messagebox.showerror("ERROR", "请选择有效的输入文件 // Invalid input file")
            return

        out_path = self.enc_output_var.get().strip()
        if not out_path:
            out_path = in_path + ".sm4"

        try:
            key = self._parse_key(self.enc_key_var.get())
        except Exception as e:
            messagebox.showerror("ERROR", f"密钥格式错误 // Invalid key: {e}")
            return

        self._set_status("// ENCRYPTING...")
        self.enc_progress.set(0)

        self._append_log(self.enc_log, f"> input   : {in_path}", COLOR_LOG_ACCENT)
        self._append_log(self.enc_log, f"> output  : {out_path}", COLOR_LOG_ACCENT)
        self._append_log(self.enc_log, f"> size    : {os.path.getsize(in_path)} bytes", COLOR_LOG_ACCENT)
        self._append_log(self.enc_log, f"> mode    : SM4-CBC-CTS", COLOR_LOG_ACCENT)
        self._append_log(self.enc_log, "----------------------------------------")

        crypto_done = [False]
        crypto_error = [None]
        crypto_stats_enc = [None]
        total_steps = 100

        def crypto_worker():
            try:
                crypto_stats_enc[0] = encrypt_file(in_path, out_path, key)
            except Exception as e:
                crypto_error[0] = e
            crypto_done[0] = True

        def animate_frame(step):
            if crypto_done[0] or step > total_steps:
                if crypto_error[0]:
                    self.enc_progress.set(1.0)
                    self._append_log(self.enc_log, f"[XX] FAILED — {crypto_error[0]}", COLOR_BORDER)
                    self._set_status("// ENCRYPTION FAILED")
                else:
                    self.enc_progress.set(1.0)
                    stats = crypto_stats_enc[0]
                    self._append_log(self.enc_log, "[OK] ENCRYPTION COMPLETE ✓", COLOR_LOG_ACCENT)
                    self._append_log(self.enc_log, f"> saved to: {out_path}", COLOR_TEXT_MUTED)
                    if stats:
                        elapsed = stats.get('elapsed_ms', 0)
                        speed = stats.get('speed_mbps', 0)
                        size = stats.get('plaintext_size', 0)
                        csize = stats.get('ciphertext_size', 0)
                        self._append_log(self.enc_log, f"> size_in : {size} bytes", COLOR_TEXT_MUTED)
                        self._append_log(self.enc_log, f"> size_out: {csize} bytes", COLOR_TEXT_MUTED)
                        self._append_log(self.enc_log, f"> time    : {elapsed:.2f} ms", COLOR_TEXT_MUTED)
                        self._append_log(self.enc_log, f"> speed   : {speed:.3f} MB/s", COLOR_YELLOW)
                    self._set_status("// ENCRYPTION COMPLETE")
                return
            progress = step / total_steps
            self.enc_progress.set(progress)
            self.after(30, lambda: animate_frame(step + 1))

        threading.Thread(target=crypto_worker, daemon=True).start()
        self.after(0, lambda: animate_frame(1))

    # ===== 解密逻辑 =====
    def _do_decrypt(self):
        in_path = self.dec_input_var.get().strip()
        if not in_path or not os.path.isfile(in_path):
            messagebox.showerror("ERROR", "请选择有效的输入文件 // Invalid input file")
            return

        out_path = self.dec_output_var.get().strip()
        if not out_path:
            if in_path.endswith(".sm4"):
                out_path = in_path[:-4]
            else:
                out_path = in_path + ".decrypted"

        try:
            key = self._parse_key(self.dec_key_var.get())
        except Exception as e:
            messagebox.showerror("ERROR", f"密钥格式错误 // Invalid key: {e}")
            return

        self._set_status("// DECRYPTING...")
        self.dec_progress.set(0)

        self._append_log(self.dec_log, f"> input   : {in_path}", COLOR_LOG_ACCENT)
        self._append_log(self.dec_log, f"> output  : {out_path}", COLOR_LOG_ACCENT)
        self._append_log(self.dec_log, f"> size    : {os.path.getsize(in_path)} bytes", COLOR_LOG_ACCENT)
        self._append_log(self.dec_log, f"> mode    : SM4-CBC-CTS", COLOR_LOG_ACCENT)
        self._append_log(self.dec_log, "----------------------------------------")

        crypto_done = [False]
        crypto_error = [None]
        crypto_stats = [None]
        total_steps = 100

        def crypto_worker():
            try:
                crypto_stats[0] = decrypt_file(in_path, out_path, key)
            except Exception as e:
                crypto_error[0] = e
            crypto_done[0] = True

        def animate_frame(step):
            if crypto_done[0] or step > total_steps:
                if crypto_error[0]:
                    self.dec_progress.set(1.0)
                    self._append_log(self.dec_log, f"[XX] FAILED — {crypto_error[0]}", COLOR_BORDER)
                    self._set_status("// DECRYPTION FAILED")
                else:
                    self.dec_progress.set(1.0)
                    stats = crypto_stats[0]
                    self._append_log(self.dec_log, "[OK] DECRYPTION COMPLETE ✓", COLOR_LOG_ACCENT)
                    self._append_log(self.dec_log, f"> saved to: {out_path}", COLOR_TEXT_MUTED)
                    if stats:
                        elapsed = stats.get('elapsed_ms', 0)
                        speed = stats.get('speed_mbps', 0)
                        psize = stats.get('plaintext_size', 0)
                        csize = stats.get('ciphertext_size', 0)
                        self._append_log(self.dec_log, f"> size_in : {csize} bytes", COLOR_TEXT_MUTED)
                        self._append_log(self.dec_log, f"> size_out: {psize} bytes", COLOR_TEXT_MUTED)
                        self._append_log(self.dec_log, f"> time    : {elapsed:.2f} ms", COLOR_TEXT_MUTED)
                        self._append_log(self.dec_log, f"> speed   : {speed:.3f} MB/s", COLOR_YELLOW)
                    self._set_status("// DECRYPTION COMPLETE")
                return
            progress = step / total_steps
            self.dec_progress.set(progress)
            self.after(30, lambda: animate_frame(step + 1))

        threading.Thread(target=crypto_worker, daemon=True).start()
        self.after(0, lambda: animate_frame(1))


# ============================================================
# 入口
# ============================================================

def run_gui():
    app = Sm4CryptoApp()
    app.mainloop()


if __name__ == "__main__":
    run_gui()