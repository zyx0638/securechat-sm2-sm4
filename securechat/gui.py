"""Tkinter views; all network and crypto work runs outside the UI thread."""

import json
import os
import queue
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

from PIL import Image, ImageTk

from .crypto import security_demo
from .protocol import Peer

GREEN = "#087f62"
INK = "#203029"
MUTED = "#64736c"
BACKGROUND = "#f4f7f5"


def format_size(size):
    if size < 1024:
        return f"{size} B"
    if size < 1024**2:
        return f"{size / 1024:.1f} KiB"
    return f"{size / 1024**2:.2f} MiB"


def fingerprint_text(value):
    return " ".join(value[i:i + 8] for i in range(0, len(value), 8))


def configure_style(root):
    root.option_add("*Text.Font", ("Microsoft YaHei UI", 10))
    root.option_add("*Listbox.Font", ("Microsoft YaHei UI", 10))
    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure(".", font=("Microsoft YaHei UI", 10), background=BACKGROUND, foreground=INK)
    style.configure("TFrame", background=BACKGROUND)
    style.configure("TLabel", background=BACKGROUND)
    style.configure("Title.TLabel", font=("Microsoft YaHei UI", 21, "bold"))
    style.configure("Sub.TLabel", foreground=MUTED, font=("Microsoft YaHei UI", 9))
    style.configure("Status.TLabel", foreground=GREEN, font=("Microsoft YaHei UI", 11, "bold"))
    style.configure("TButton", padding=(10, 7), background="#e7ede9", borderwidth=0)
    style.map("TButton", background=[("active", "#d9e7de"), ("disabled", "#edf0ee")],
              foreground=[("disabled", "#98a49c")])
    style.configure("Primary.TButton", background=GREEN, foreground="white")
    style.map("Primary.TButton", background=[("active", "#066c53"), ("disabled", "#c6d9ce")],
              foreground=[("disabled", "#64736c")])
    style.configure("TNotebook", borderwidth=0)
    style.configure("TNotebook.Tab", padding=(17, 9))
    style.map("TNotebook.Tab", background=[("selected", "#ffffff")], foreground=[("selected", GREEN)])
    style.configure("Horizontal.TProgressbar", background=GREEN, troughcolor="#dfe9e3", borderwidth=0)
    style.configure("Treeview", rowheight=30, background="white", fieldbackground="white")


class ChatWindow:
    def __init__(self, window, name, identity, directory, close_callback=None):
        self.window, self.name, self.identity = window, name, identity
        self.directory = Path(directory)
        self.close_callback = close_callback
        self.events = queue.Queue()
        self.peer = Peer(name, identity, directory, self.events.put, self.ask_trust)
        self.closed = False
        self.dialogs = []
        self.pending_decisions = []
        self.images = []
        self.received = []
        self.send_busy = False
        self.text_pending = False
        self.connected = False
        self.window.title(f"密语 · {name} | 密码学中级实验")
        self.window.minsize(680, 650)
        self.window.configure(background=BACKGROUND)
        self._build()
        self.window.protocol("WM_DELETE_WINDOW", self.close)
        self.poll_id = self.window.after(80, self.poll)

    def _build(self):
        outer = ttk.Frame(self.window, padding=18)
        outer.pack(fill="both", expand=True)
        header = ttk.Frame(outer)
        header.pack(fill="x")
        ttk.Label(header, text="密语", style="Title.TLabel").pack(side="left")
        ttk.Label(header, text="安全通信实验", style="Sub.TLabel", padding=(12, 8)).pack(side="left")
        ttk.Label(header, text=self.name, font=("Microsoft YaHei UI", 14, "bold")).pack(side="right")
        self.status = tk.StringVar(value="未连接")
        ttk.Label(outer, textvariable=self.status, style="Status.TLabel", padding=(0, 10)).pack(anchor="w")

        identity_strip = ttk.Frame(outer)
        identity_strip.pack(fill="x", pady=(0, 10))
        ttk.Label(identity_strip, text="本机身份 · SM3", style="Sub.TLabel").pack(anchor="w")
        ttk.Label(identity_strip, text=fingerprint_text(self.identity.fingerprint),
                  font=("Consolas", 9)).pack(anchor="w")

        connection = ttk.Frame(outer)
        connection.pack(fill="x", pady=(0, 12))
        ttk.Label(connection, text="地址").grid(row=0, column=0, padx=(0, 6))
        self.host = tk.StringVar(value="127.0.0.1")
        self.host_entry = ttk.Entry(connection, textvariable=self.host, width=15)
        self.host_entry.grid(row=0, column=1, sticky="ew", padx=(0, 10))
        ttk.Label(connection, text="端口").grid(row=0, column=2, padx=(0, 6))
        self.port = tk.StringVar(value="8765")
        self.port_entry = ttk.Entry(connection, textvariable=self.port, width=6)
        self.port_entry.grid(row=0, column=3, padx=(0, 10))
        self.listen_button = ttk.Button(connection, text="开始监听", command=self.listen)
        self.listen_button.grid(row=0, column=4, padx=(0, 6))
        self.connect_button = ttk.Button(connection, text="连接对端", command=self.connect, style="Primary.TButton")
        self.connect_button.grid(row=0, column=5, padx=(0, 6))
        self.disconnect_button = ttk.Button(connection, text="断开", command=self.peer.close, state="disabled")
        self.disconnect_button.grid(row=0, column=6)
        connection.columnconfigure(1, weight=1)

        self.notebook = ttk.Notebook(outer)
        self.notebook.pack(fill="both", expand=True)
        chat_tab = ttk.Frame(self.notebook, padding=(0, 12, 0, 0))
        identity_tab = ttk.Frame(self.notebook, padding=14)
        laboratory = ttk.Frame(self.notebook, padding=14)
        self.notebook.add(chat_tab, text="通信")
        self.notebook.add(identity_tab, text="会话与身份")
        self.notebook.add(laboratory, text="安全实验")

        self.chat = ScrolledText(chat_tab, wrap="word", height=12, relief="flat", borderwidth=0,
                                 padx=14, pady=12, background="white", foreground=INK, state="disabled")
        self.chat.pack(fill="both", expand=True)
        for tag, color in (("me", GREEN), ("peer", "#176a9b"), ("system", MUTED), ("error", "#ac3d30")):
            self.chat.tag_configure(tag, foreground=color, spacing1=8, spacing3=4)
        toolbar = ttk.Frame(chat_tab)
        toolbar.pack(fill="x", pady=(10, 6))
        self.image_button = ttk.Button(toolbar, text="发送图片", command=lambda: self.choose_file("image"), state="disabled")
        self.image_button.pack(side="left", padx=(0, 6))
        self.video_button = ttk.Button(toolbar, text="发送视频", command=lambda: self.choose_file("video"), state="disabled")
        self.video_button.pack(side="left", padx=(0, 6))
        self.file_button = ttk.Button(toolbar, text="发送文件", command=lambda: self.choose_file("file"), state="disabled")
        self.file_button.pack(side="left", padx=(0, 6))
        ttk.Button(toolbar, text="接收目录", command=self.open_inbox).pack(side="right")
        self.composer = tk.Text(chat_tab, height=3, wrap="word", relief="solid", borderwidth=1,
                                background="white", padx=10, pady=7, font=("Microsoft YaHei UI", 10))
        self.composer.pack(fill="x")
        self.composer.bind("<Control-Return>", lambda event: self.send_text())
        send_row = ttk.Frame(chat_tab)
        send_row.pack(fill="x", pady=(6, 8))
        self.transfer_status = tk.StringVar(value="尚无文件传输")
        ttk.Label(send_row, textvariable=self.transfer_status, style="Sub.TLabel").pack(side="left")
        self.send_button = ttk.Button(send_row, text="发送", style="Primary.TButton", command=self.send_text, state="disabled")
        self.send_button.pack(side="right")
        self.progress = ttk.Progressbar(chat_tab, maximum=100)
        self.progress.pack(fill="x")

        ttk.Label(identity_tab, text="密码套件", font=("Microsoft YaHei UI", 12, "bold")).pack(anchor="w", pady=(0, 8))
        table = ttk.Treeview(identity_tab, columns=("role", "algorithm"), show="headings", height=6)
        table.heading("role", text="用途")
        table.heading("algorithm", text="算法")
        table.column("role", width=150, stretch=False)
        table.column("algorithm", width=400)
        for row in (("身份签名与公钥加密", "SM2 + SM3 / 加密随机挑战"), ("临时密钥协商", "X25519"),
                    ("会话密钥派生", "HKDF-SM3 / 双向独立密钥"), ("消息加密", "SM4-CBC + PKCS7"),
                    ("消息认证 / 重放防护", "HMAC-SM3 / 连续序号"), ("本地私钥保护", "scrypt + AES-256-GCM")):
            table.insert("", "end", values=row)
        table.pack(fill="x")
        self.session_info = ScrolledText(identity_tab, height=10, wrap="word", relief="flat", padx=12, pady=10,
                                         background="white", font=("Consolas", 10), state="disabled")
        self.session_info.pack(fill="both", expand=True, pady=12)
        self.set_session("本机 SM2 身份公钥\n" + self.identity.public + "\n\n尚未建立会话。")
        identity_actions = ttk.Frame(identity_tab)
        identity_actions.pack(fill="x")
        ttk.Button(identity_actions, text="复制本机指纹", command=self.copy_fingerprint).pack(side="left")
        ttk.Button(identity_actions, text="查看信任记录", command=self.show_trust).pack(side="left", padx=8)
        ttk.Button(identity_actions, text="清除信任记录", command=self.clear_trust).pack(side="left")

        lab_actions = ttk.Frame(laboratory)
        lab_actions.pack(fill="x", pady=(0, 10))
        self.lab_button = ttk.Button(lab_actions, text="运行篡改与重放实验", command=self.run_lab, style="Primary.TButton")
        self.lab_button.pack(side="left")
        ttk.Button(lab_actions, text="导出实验日志", command=self.export_log).pack(side="right")
        self.lab_log = ScrolledText(laboratory, height=15, wrap="word", relief="flat", padx=12, pady=10,
                                    background="white", state="disabled", font=("Microsoft YaHei UI", 10))
        self.lab_log.pack(fill="both", expand=True)
        self.log_lines = []
        self.log("身份已解锁；私钥文件使用口令加密。")

    def append_chat(self, text, tag="system"):
        self.chat.configure(state="normal")
        self.chat.insert("end", f"{time.strftime('%H:%M:%S')}  {text}\n", tag)
        self.chat.configure(state="disabled")
        self.chat.see("end")

    def log(self, text):
        line = f"{time.strftime('%H:%M:%S')}  {text}"
        self.log_lines.append(line)
        self.lab_log.configure(state="normal")
        self.lab_log.insert("end", line + "\n\n")
        self.lab_log.configure(state="disabled")
        self.lab_log.see("end")

    def set_session(self, text):
        self.session_info.configure(state="normal")
        self.session_info.delete("1.0", "end")
        self.session_info.insert("end", text)
        self.session_info.configure(state="disabled")

    def set_connection_state(self, busy=False, connected=False):
        self.connected = connected
        for widget in (self.host_entry, self.port_entry, self.connect_button, self.listen_button):
            widget.configure(state="disabled" if busy else "normal")
        self.disconnect_button.configure(state="normal" if busy else "disabled")
        self.send_button.configure(state="normal" if connected and not self.text_pending else "disabled")
        self.set_file_controls()

    def set_file_controls(self):
        for button in (self.image_button, self.video_button, self.file_button):
            button.configure(state="normal" if self.connected and not self.send_busy else "disabled")

    def address(self):
        port = int(self.port.get())
        host = self.host.get().strip()
        if not host or not 1 <= port <= 65535:
            raise ValueError("请输入有效地址和 1–65535 之间的端口")
        return host, port

    def listen(self):
        try:
            self.peer.listen(*self.address())
            self.set_connection_state(busy=True)
        except (ValueError, OSError) as exc:
            messagebox.showerror("监听失败", str(exc), parent=self.window)

    def connect(self):
        try:
            self.peer.connect(*self.address())
            self.set_connection_state(busy=True)
        except (ValueError, OSError) as exc:
            messagebox.showerror("连接失败", str(exc), parent=self.window)

    def run_worker(self, function, *args, finished=None):
        def work():
            try:
                function(*args)
            except Exception as exc:
                self.events.put({"type": "operation_error", "message": str(exc)})
            finally:
                if finished:
                    self.events.put({"type": finished})
        threading.Thread(target=work, daemon=True).start()

    def send_text(self):
        text = self.composer.get("1.0", "end-1c")
        if not self.connected or self.text_pending or not text.strip():
            return "break"
        if len(text.encode("utf-8")) > 32768:
            messagebox.showerror("消息过长", "单条消息最多 32 KiB。", parent=self.window)
            return "break"
        self.text_pending = True
        self.send_button.configure(state="disabled")
        self.run_worker(self.peer.send_text, text, finished="text_idle")
        return "break"

    def choose_file(self, kind):
        filters = {"image": [("图片", "*.png *.jpg *.jpeg *.gif *.bmp *.webp")],
                   "video": [("视频", "*.mp4 *.avi *.mov *.mkv *.webm")], "file": []}
        path = filedialog.askopenfilename(parent=self.window, title="选择发送文件",
                                          initialdir=str(Path.cwd() / "samples"),
                                          filetypes=filters[kind] + [("所有文件", "*.*")])
        if path:
            self.send_file(path, kind)

    def send_file(self, path, kind):
        if not self.connected or self.send_busy:
            return
        self.send_busy = True
        self.set_file_controls()
        self.run_worker(self.peer.send_file, path, kind, finished="transfer_idle")

    def ask_trust(self, name, fingerprint):
        decision, result = threading.Event(), {"accepted": False}
        self.events.put({"type": "trust_request", "name": name, "fingerprint": fingerprint,
                         "decision": decision, "result": result})
        deadline = time.monotonic() + 115
        while not decision.wait(0.2):
            connection = self.peer.connection
            if self.closed or connection is None or connection.stop.is_set() or time.monotonic() > deadline:
                return False
        return result["accepted"]

    def trust_dialog(self, event):
        dialog = tk.Toplevel(self.window)
        dialog.title(f"{self.name} · 核验对端身份")
        dialog.transient(self.window)
        dialog.resizable(False, False)
        body = ttk.Frame(dialog, padding=20)
        body.pack(fill="both", expand=True)
        ttk.Label(body, text=f"首次连接：{event['name']}", font=("Microsoft YaHei UI", 14, "bold")).pack(anchor="w")
        ttk.Label(body, text="本机指纹", style="Sub.TLabel").pack(anchor="w", pady=(16, 4))
        local = fingerprint_text(self.identity.fingerprint)
        remote = fingerprint_text(event["fingerprint"])
        for title, value in ((None, local), ("对端指纹", remote)):
            if title:
                ttk.Label(body, text=title, style="Sub.TLabel").pack(anchor="w", pady=(12, 4))
            entry = ttk.Entry(body, width=74, font=("Consolas", 10))
            entry.insert(0, value)
            entry.configure(state="readonly")
            entry.pack(fill="x")
        ttk.Label(body, text="请通过可信渠道核对对方界面上的完整本机指纹。", padding=(0, 15)).pack(anchor="w")
        buttons = ttk.Frame(body)
        buttons.pack(fill="x")

        def decide(accepted):
            event["result"]["accepted"] = accepted
            event["decision"].set()
            if dialog.winfo_exists():
                dialog.destroy()
        ttk.Button(buttons, text="拒绝连接", command=lambda: decide(False)).pack(side="left")
        ttk.Button(buttons, text="已核对，信任此身份", style="Primary.TButton", command=lambda: decide(True)).pack(side="right")
        dialog.protocol("WM_DELETE_WINDOW", lambda: decide(False))
        x = self.window.winfo_rootx() + 25
        y = self.window.winfo_rooty() + 160
        dialog.geometry(f"+{max(0, x)}+{max(0, y)}")
        self.dialogs.append(dialog)
        self.pending_decisions.append(event)

    def poll(self):
        if self.closed:
            return
        for _ in range(150):
            try:
                event = self.events.get_nowait()
            except queue.Empty:
                break
            self.handle_event(event)
        self.poll_id = self.window.after(80, self.poll)

    def handle_event(self, event):
        kind = event["type"]
        if kind == "trust_request":
            self.status.set("等待核验对端身份")
            self.trust_dialog(event)
        elif kind == "listening":
            self.status.set(f"等待对端连接 · {event['host']}:{event['port']}")
            self.append_chat("已开始监听。")
        elif kind == "connecting":
            self.status.set(f"正在连接 · {event['host']}:{event['port']}")
        elif kind == "handshake":
            self.log("SM2 签名验证通过；已完成 X25519 协商与 HKDF-SM3 派生。")
        elif kind == "asymmetric_verified":
            self.log("SM2 公钥加密随机挑战验证通过；双方均能正确解密。")
        elif kind == "connected":
            self.set_connection_state(busy=True, connected=True)
            self.status.set(f"安全连接 · {event['peer']}")
            self.append_chat(f"已与 {event['peer']} 建立加密会话。")
            self.set_session(f"对端：{event['peer']}\n\n对端 SM3 指纹\n{event['fingerprint']}\n\n"
                             f"会话标识（非密钥）\n{event['session']}\n\n"
                             "SM2 身份验证通过\n双向会话密钥确认通过\nSM4 加密 / HMAC-SM3 验证已启用")
            self.log("双方身份已确认，会话密钥确认通过。会话标识：" + event["session"])
        elif kind == "disconnected":
            self.set_connection_state()
            self.status.set("未连接")
            for dialog in self.dialogs:
                if dialog.winfo_exists():
                    dialog.destroy()
            for decision in self.pending_decisions:
                decision["decision"].set()
            self.dialogs.clear()
            self.pending_decisions.clear()
            self.append_chat("会话已结束。")
        elif kind in ("error", "operation_error"):
            self.append_chat("操作失败：" + event["message"], "error")
            self.log("拒绝或错误：" + event["message"])
        elif kind == "text":
            self.append_chat(f"{event['peer']}\n{event['text']}", "peer")
        elif kind == "text_sent":
            self.append_chat("我\n" + event["text"], "me")
            if self.composer.get("1.0", "end-1c") == event["text"]:
                self.composer.delete("1.0", "end")
        elif kind == "text_idle":
            self.text_pending = False
            self.send_button.configure(state="normal" if self.connected else "disabled")
        elif kind == "wire":
            self.log(f"发送密文记录 #{event['sequence']} · {event['size']} B\n{event['preview']}…")
        elif kind == "progress":
            total = event["total"]
            self.progress["value"] = event["done"] * 100 / total if total else 100
            action = "发送" if event["direction"] == "send" else "接收"
            self.transfer_status.set(f"{action} · {format_size(event['done'])} / {format_size(total)}")
        elif kind in ("file_received", "file_sent"):
            received = kind == "file_received"
            action = "收到" if received else "对端已校验接收"
            self.append_chat(f"{action}：{event['name']} · {format_size(event['size'])}\nSM3：{event['sm3']}",
                             "peer" if received else "me")
            self.log(f"{action}文件：{event['name']}\n大小：{event['size']} B\n"
                     f"SM3：{event['sm3']}\n耗时：{event['seconds']:.3f} s")
            self.transfer_status.set(f"{action} · {format_size(event['size'])}")
            self.progress["value"] = 100
            if received:
                self.received.append(event)
                if event["kind"] == "image":
                    self.preview_image(event["path"])
        elif kind == "transfer_idle":
            self.send_busy = False
            self.set_file_controls()
        elif kind == "lab_result":
            result = event["result"]
            self.log("独立测试通道\n篡改密文：" + ("已拒绝" if result["tamper_rejected"] else "失败") +
                     "\n重复记录：" + ("已拒绝" if result["replay_rejected"] else "失败") +
                     "\n密文样本：" + result["ciphertext"])
        elif kind == "lab_idle":
            self.lab_button.configure(state="normal")

    def preview_image(self, path):
        try:
            with Image.open(path) as image:
                if image.width * image.height > 20_000_000:
                    self.log("图片尺寸过大，已保留文件并跳过预览。")
                    return
                image.thumbnail((360, 190))
                photo = ImageTk.PhotoImage(image.copy(), master=self.window)
            self.images.append(photo)
            self.chat.configure(state="normal")
            self.chat.image_create("end", image=photo)
            self.chat.insert("end", "\n")
            self.chat.configure(state="disabled")
            self.chat.see("end")
        except (OSError, ValueError, Image.DecompressionBombError) as exc:
            self.log("文件已校验保存，但图片预览不可用：" + str(exc))

    def run_lab(self):
        self.lab_button.configure(state="disabled")
        def work():
            self.events.put({"type": "lab_result", "result": security_demo()})
        self.run_worker(work, finished="lab_idle")

    def open_inbox(self):
        os.startfile(str(self.peer.inbox.resolve()))

    def copy_fingerprint(self):
        self.window.clipboard_clear()
        self.window.clipboard_append(self.identity.fingerprint)

    def show_trust(self):
        path = self.peer.trust.path
        try:
            records = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
            content = "\n\n".join(f"{name}\n{value}" for name, value in records.items()) or "尚无已确认的对端身份。"
            messagebox.showinfo("已保存的信任记录", content, parent=self.window)
        except (OSError, ValueError) as exc:
            messagebox.showerror("读取失败", str(exc), parent=self.window)

    def clear_trust(self):
        if self.peer.connection is not None:
            messagebox.showinfo("请先断开", "连接或监听结束后才能清除信任记录。", parent=self.window)
            return
        if messagebox.askyesno("清除信任记录", "下次连接需要重新核验完整指纹，确定清除？", parent=self.window):
            self.peer.trust.path.unlink(missing_ok=True)
            self.log("用户清除了本地对端信任记录。")

    def export_log(self):
        path = filedialog.asksaveasfilename(parent=self.window, title="导出实验日志", defaultextension=".txt",
                                           initialfile=f"{self.name}-实验日志.txt", filetypes=[("文本", "*.txt")])
        if path:
            Path(path).write_text("\n\n".join(self.log_lines), encoding="utf-8")

    def close(self):
        if self.closed:
            return
        self.closed = True
        self.window.after_cancel(self.poll_id)
        for event in self.pending_decisions:
            event["decision"].set()
        self.peer.close()
        if self.close_callback:
            self.close_callback(self)
        else:
            self.window.destroy()
