# -*- coding: utf-8 -*-
"""
SM4 文件加密系统 - 现代化图形界面
使用 CustomTkinter (https://github.com/TomSchimansky/CustomTkinter)

运行前: pip install customtkinter
"""

import os
import sys
import threading
import traceback
from tkinter import filedialog, messagebox

import customtkinter as ctk

from sm4_engine import key_expansion, sm4_encrypt_block, sm4_decrypt_block
from file_crypto import encrypt_file, decrypt_file

DEFAULT_KEY = bytes.fromhex("0123456789abcdeffedcba9876543210")


# ------------------------------------------------------------
# 主题与样式
# ------------------------------------------------------------
ctk.set_appearance_mode("dark")        # "dark" / "light" / "system"
ctk.set_default_color_theme("blue")     # "blue" / "dark-blue" / "green"


# ============================================================
# 主应用
# ============================================================
class Sm4CryptoApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("SM4 文件加密系统")
        self.geometry("800x620")
        self.minsize(720, 560)

        # 栅格布局
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # ---- 顶部标题栏 ----
        self.header = ctk.CTkFrame(self, corner_radius=12)
        self.header.grid(row=0, column=0, padx=16, pady=(16, 0), sticky="nsew")
        self.header.grid_columnconfigure(0, weight=1)

        title = ctk.CTkLabel(
            self.header,
            text="🔐 SM4 文件加密系统",
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color="#58A6FF"
        )
        title.grid(row=0, column=0, padx=20, pady=(14, 4), sticky="w")

        subtitle = ctk.CTkLabel(
            self.header,
            text="CBC 密文链接 + CTS 密文挪用  ·  支持任意二进制文件",
            font=ctk.CTkFont(size=12),
            text_color="gray70"
        )
        subtitle.grid(row=1, column=0, padx=20, pady=(0, 12), sticky="w")

        # ---- 主体 (Tabview: 加密 / 解密 / 关于) ----
        self.tabview = ctk.CTkTabview(self, corner_radius=12)
        self.tabview.grid(row=1, column=0, padx=16, pady=16, sticky="nsew")
        self.tabview.add("加密文件")
        self.tabview.add("解密文件")
        self.tabview.grid_columnconfigure(0, weight=1)

        self._build_encrypt_tab(self.tabview.tab("加密文件"))
        self._build_decrypt_tab(self.tabview.tab("解密文件"))

        # ---- 底部状态栏 ----
        self.status_var = ctk.StringVar(value="就绪")
        self.status_bar = ctk.CTkLabel(
            self, textvariable=self.status_var,
            anchor="w", text_color="gray70",
            font=ctk.CTkFont(size=11), height=24
        )
        self.status_bar.grid(row=2, column=0, padx=20, pady=(0, 8), sticky="ew")

    # ============================================================
    # 加密 Tab
    # ============================================================
    def _build_encrypt_tab(self, parent):
        parent.grid_columnconfigure(1, weight=1)

        self.enc_input_var = ctk.StringVar()
        self.enc_output_var = ctk.StringVar()
        self.enc_key_var = ctk.StringVar(value=DEFAULT_KEY.hex())
        self.enc_progress_var = ctk.DoubleVar(value=0.0)
        self.enc_result_var = ctk.StringVar(value="")

        ctk.CTkLabel(parent, text="选择要加密的文件:", font=ctk.CTkFont(weight="bold")
                     ).grid(row=0, column=0, padx=16, pady=(20, 4), sticky="w")

        row = 1
        ctk.CTkEntry(parent, textvariable=self.enc_input_var,
                     placeholder_text="点击右侧按钮选择文件...", height=36
                     ).grid(row=row, column=0, columnspan=2, padx=16, pady=4, sticky="ew")

        ctk.CTkButton(parent, text="📂  浏览...", width=110, height=36,
                       command=lambda: self._browse_file(self.enc_input_var, save=False)
                       ).grid(row=row, column=2, padx=(0, 16), pady=4)

        row = 2
        ctk.CTkLabel(parent, text="输出文件 (自动生成):", font=ctk.CTkFont(weight="bold")
                     ).grid(row=row, column=0, padx=16, pady=(12, 4), sticky="w")

        row = 3
        ctk.CTkEntry(parent, textvariable=self.enc_output_var,
                     placeholder_text="留空则自动添加 .sm4 后缀", height=36
                     ).grid(row=row, column=0, columnspan=2, padx=16, pady=4, sticky="ew")
        ctk.CTkButton(parent, text="📁  另存为...", width=110, height=36,
                       command=lambda: self._browse_file(self.enc_output_var, save=True)
                       ).grid(row=row, column=2, padx=(0, 16), pady=4)

        row = 4
        ctk.CTkLabel(parent, text="密钥 (16 字节 = 32 hex 字符):", font=ctk.CTkFont(weight="bold")
                     ).grid(row=row, column=0, padx=16, pady=(12, 4), sticky="w")

        row = 5
        ctk.CTkEntry(parent, textvariable=self.enc_key_var, height=36,
                     show="•"
                     ).grid(row=row, column=0, columnspan=2, padx=16, pady=4, sticky="ew")
        ctk.CTkButton(parent, text="👁", width=60, height=36,
                       command=lambda: self._toggle_password(self.enc_key_var)
                       ).grid(row=row, column=2, padx=(0, 16), pady=4)

        row = 6
        ctk.CTkButton(parent, text="🔒  开始加密",
                       font=ctk.CTkFont(size=14, weight="bold"),
                       height=44, corner_radius=10,
                       fg_color="#2F855A", hover_color="#276749",
                       command=self._do_encrypt
                       ).grid(row=row, column=0, columnspan=3, padx=16, pady=(20, 4), sticky="ew")

        row = 7
        self.enc_progress = ctk.CTkProgressBar(parent, height=12, corner_radius=6)
        self.enc_progress.set(0)
        self.enc_progress.grid(row=row, column=0, columnspan=3, padx=16, pady=8, sticky="ew")

        row = 8
        ctk.CTkTextbox(parent, height=140, corner_radius=10,
                        text_color="#E0E0E0", font=ctk.CTkFont(family="Consolas", size=12)
                        ).grid(row=row, column=0, columnspan=3, padx=16, pady=(4, 16), sticky="nsew")
        self.enc_log = parent.grid_slaves(row=row, column=0)[0]
        self.enc_log.insert("0.0", "等待加密...\n")
        self.enc_log.configure(state="disabled")

    # ============================================================
    # 解密 Tab
    # ============================================================
    def _build_decrypt_tab(self, parent):
        parent.grid_columnconfigure(1, weight=1)

        self.dec_input_var = ctk.StringVar()
        self.dec_output_var = ctk.StringVar()
        self.dec_key_var = ctk.StringVar(value=DEFAULT_KEY.hex())

        ctk.CTkLabel(parent, text="选择要解密的文件 (.sm4):", font=ctk.CTkFont(weight="bold")
                     ).grid(row=0, column=0, padx=16, pady=(20, 4), sticky="w")

        row = 1
        ctk.CTkEntry(parent, textvariable=self.dec_input_var,
                     placeholder_text="点击右侧按钮选择文件...", height=36
                     ).grid(row=row, column=0, columnspan=2, padx=16, pady=4, sticky="ew")
        ctk.CTkButton(parent, text="📂  浏览...", width=110, height=36,
                       command=lambda: self._browse_file(self.dec_input_var, save=False)
                       ).grid(row=row, column=2, padx=(0, 16), pady=4)

        row = 2
        ctk.CTkLabel(parent, text="输出文件:", font=ctk.CTkFont(weight="bold")
                     ).grid(row=row, column=0, padx=16, pady=(12, 4), sticky="w")

        row = 3
        ctk.CTkEntry(parent, textvariable=self.dec_output_var,
                     placeholder_text="留空则自动生成输出路径", height=36
                     ).grid(row=row, column=0, columnspan=2, padx=16, pady=4, sticky="ew")
        ctk.CTkButton(parent, text="📁  另存为...", width=110, height=36,
                       command=lambda: self._browse_file(self.dec_output_var, save=True)
                       ).grid(row=row, column=2, padx=(0, 16), pady=4)

        row = 4
        ctk.CTkLabel(parent, text="密钥:", font=ctk.CTkFont(weight="bold")
                     ).grid(row=row, column=0, padx=16, pady=(12, 4), sticky="w")

        row = 5
        ctk.CTkEntry(parent, textvariable=self.dec_key_var, height=36, show="•"
                     ).grid(row=row, column=0, columnspan=2, padx=16, pady=4, sticky="ew")
        ctk.CTkButton(parent, text="👁", width=60, height=36,
                       command=lambda: self._toggle_password(self.dec_key_var)
                       ).grid(row=row, column=2, padx=(0, 16), pady=4)

        row = 6
        ctk.CTkButton(parent, text="🔓  开始解密",
                       font=ctk.CTkFont(size=14, weight="bold"),
                       height=44, corner_radius=10,
                       fg_color="#DD6B20", hover_color="#C05621",
                       command=self._do_decrypt
                       ).grid(row=row, column=0, columnspan=3, padx=16, pady=(20, 4), sticky="ew")

        row = 7
        self.dec_progress = ctk.CTkProgressBar(parent, height=12, corner_radius=6)
        self.dec_progress.set(0)
        self.dec_progress.grid(row=row, column=0, columnspan=3, padx=16, pady=8, sticky="ew")

        row = 8
        ctk.CTkTextbox(parent, height=140, corner_radius=10,
                        text_color="#E0E0E0", font=ctk.CTkFont(family="Consolas", size=12)
                        ).grid(row=row, column=0, columnspan=3, padx=16, pady=(4, 16), sticky="nsew")
        self.dec_log = parent.grid_slaves(row=row, column=0)[0]
        self.dec_log.insert("0.0", "等待解密...\n")
        self.dec_log.configure(state="disabled")

    # ============================================================
    # 工具函数
    # ============================================================
    def _browse_file(self, var: ctk.StringVar, save: bool):
        if save:
            path = filedialog.asksaveasfilename(
                title="选择输出文件",
                defaultextension=".sm4",
                filetypes=[("所有文件", "*.*")]
            )
        else:
            path = filedialog.askopenfilename(
                title="选择文件",
                filetypes=[("所有文件", "*.*")]
            )
        if path:
            var.set(path)

    def _toggle_password(self, var: ctk.StringVar):
        # 找到对应的 entry (简单实现: 重新 prompt 一次)
        key = var.get()
        shown = messagebox.showinfo("密钥", f"当前密钥:\n{key}")

    def _set_status(self, text: str):
        self.status_var.set(text)

    def _append_log(self, textbox: ctk.CTkTextbox, msg: str):
        textbox.configure(state="normal")
        textbox.insert("end", msg + "\n")
        textbox.see("end")
        textbox.configure(state="disabled")
        textbox.update_idletasks()

    def _parse_key(self, hex_str: str) -> bytes:
        try:
            key = bytes.fromhex(hex_str.strip())
        except ValueError:
            raise ValueError("密钥必须是十六进制字符串 (32 个字符 = 16 字节)")
        if len(key) != 16:
            raise ValueError(f"密钥长度必须为 16 字节 (32 hex), 当前 {len(key)} 字节")
        return key

    # ============================================================
    # 加密 / 解密动作 (后台线程, 不阻塞 UI)
    # ============================================================
    def _do_encrypt(self):
        in_path = self.enc_input_var.get().strip()
        out_path = self.enc_output_var.get().strip()

        if not in_path or not os.path.isfile(in_path):
            messagebox.showerror("错误", "请选择有效的输入文件")
            return

        if not out_path:
            out_path = in_path + ".sm4"

        try:
            key = self._parse_key(self.enc_key_var.get())
        except ValueError as e:
            messagebox.showerror("密钥格式错误", str(e))
            return

        self._set_status("正在加密...")
        self.enc_progress.set(0)
        self.enc_log.configure(state="normal")
        self.enc_log.delete("0.0", "end")
        self.enc_log.insert("0.0", "")
        self.enc_log.configure(state="disabled")

        def worker():
            try:
                self._append_log(self.enc_log, f"> 输入: {in_path}")
                self._append_log(self.enc_log, f"> 输出: {out_path}")
                self._append_log(self.enc_log,
                                 f"> 文件大小: {os.path.getsize(in_path):,} 字节")
                stats = encrypt_file(in_path, out_path, key)
                self._append_log(self.enc_log,
                                 f"> 完成! 密文 {stats['ciphertext_size']:,} 字节  ·  "
                                 f"{stats['elapsed_ms']:.2f} ms  ·  "
                                 f"{stats['speed_mbps']:.3f} MB/s")
                self.enc_progress.set(1.0)
                self._set_status("加密完成 ✓")
                messagebox.showinfo("成功",
                                      f"加密完成!\n\n密文文件: {out_path}\n"
                                      f"速度: {stats['speed_mbps']:.3f} MB/s")
            except Exception as e:
                self.enc_progress.set(0)
                self._set_status("加密失败 ✗")
                self._append_log(self.enc_log, f"[错误] {e}")
                self._append_log(self.enc_log, traceback.format_exc())
                messagebox.showerror("加密失败", str(e))

        threading.Thread(target=worker, daemon=True).start()

    def _do_decrypt(self):
        in_path = self.dec_input_var.get().strip()
        out_path = self.dec_output_var.get().strip()

        if not in_path or not os.path.isfile(in_path):
            messagebox.showerror("错误", "请选择有效的输入文件")
            return

        if not out_path:
            base = in_path
            if base.lower().endswith('.sm4'):
                original_path = base[:-4]                    # e.g. 报告.docx
                name, ext = os.path.splitext(original_path)   # name="报告", ext=".docx"
                out_path = name + "_已解密" + ext             # → "报告_已解密.docx"
            else:
                out_path = base + ".decrypted"

        try:
            key = self._parse_key(self.dec_key_var.get())
        except ValueError as e:
            messagebox.showerror("密钥格式错误", str(e))
            return

        self._set_status("正在解密...")
        self.dec_progress.set(0)
        self.dec_log.configure(state="normal")
        self.dec_log.delete("0.0", "end")
        self.dec_log.insert("0.0", "")
        self.dec_log.configure(state="disabled")

        def worker():
            try:
                self._append_log(self.dec_log, f"> 输入: {in_path}")
                self._append_log(self.dec_log, f"> 输出: {out_path}")
                stats = decrypt_file(in_path, out_path, key)
                self._append_log(self.dec_log,
                                 f"> 完成! 明文 {stats['plaintext_size']:,} 字节  ·  "
                                 f"{stats['elapsed_ms']:.2f} ms  ·  "
                                 f"{stats['speed_mbps']:.3f} MB/s")
                self.dec_progress.set(1.0)
                self._set_status("解密完成 ✓")
                messagebox.showinfo("成功",
                                      f"解密完成!\n\n输出文件: {out_path}\n"
                                      f"速度: {stats['speed_mbps']:.3f} MB/s")
            except Exception as e:
                self.dec_progress.set(0)
                self._set_status("解密失败 ✗")
                self._append_log(self.dec_log, f"[错误] {e}")
                self._append_log(self.dec_log, traceback.format_exc())
                messagebox.showerror("解密失败", str(e))

        threading.Thread(target=worker, daemon=True).start()


def run_gui():
    app = Sm4CryptoApp()
    app.mainloop()


if __name__ == '__main__':
    run_gui()