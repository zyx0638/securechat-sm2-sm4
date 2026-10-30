"""Desktop entry point. Run with --demo for a local two-peer demonstration."""

import argparse
import sys
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, simpledialog, ttk

from securechat.crypto import Identity, SecurityError
from securechat.gui import ChatWindow, configure_style


def unlock(root, profiles, directory):
    while True:
        existing = any((directory / profile / "identity.json").exists() for profile in profiles)
        prompt = "输入身份文件的解锁口令：" if existing else "设置身份保护口令（至少 8 个字符）："
        password = simpledialog.askstring("密语 · 身份保护", prompt, show="*", parent=root)
        if password is None:
            return None
        if len(password) < 8:
            messagebox.showerror("口令过短", "请使用至少 8 个字符的口令。", parent=root)
            continue
        if not existing:
            repeated = simpledialog.askstring("确认口令", "再次输入身份保护口令：", show="*", parent=root)
            if repeated != password:
                messagebox.showerror("口令不一致", "两次口令输入不一致，请重新设置。", parent=root)
                continue
        identities = {}
        try:
            for profile in profiles:
                path = directory / profile / "identity.json"
                identities[profile] = Identity.load(path, password) if path.exists() else Identity.generate()
            for profile in profiles:
                path = directory / profile / "identity.json"
                if not path.exists():
                    identities[profile].save(path, password)
            return identities
        except (SecurityError, OSError) as exc:
            messagebox.showerror("身份解锁失败", str(exc), parent=root)


def main():
    parser = argparse.ArgumentParser(description="Cryptography laboratory secure chat")
    parser.add_argument("--demo", action="store_true", help="Open Alice and Bob on this computer")
    parser.add_argument("--name", default="Alice", choices=("Alice", "Bob"))
    parser.add_argument("--data-dir", type=Path, default=Path(__file__).resolve().parent / "runtime")
    args = parser.parse_args()
    root = tk.Tk()
    root.title("密语 · 身份保护")
    root.geometry("440x180")
    configure_style(root)
    ttk.Label(root, text="密语", style="Title.TLabel", padding=22).pack(anchor="w")
    ttk.Label(root, text="正在准备通信身份", padding=(22, 0)).pack(anchor="w")
    root.update()
    profiles = ["Alice", "Bob"] if args.demo else [args.name]
    identities = unlock(root, profiles, args.data_dir)
    if identities is None:
        root.destroy()
        return
    for child in root.winfo_children():
        child.destroy()
    windows = []

    def close_one(view):
        if view.window is root:
            for current in windows:
                current.closed = True
                current.peer.close()
            root.destroy()
        else:
            view.window.destroy()

    screen_width, screen_height = root.winfo_screenwidth(), root.winfo_screenheight()
    width = min(860, max(700, (screen_width - 48) // 2)) if args.demo else min(1000, screen_width - 60)
    height = min(900, screen_height - 90)
    for index, profile in enumerate(profiles):
        window = root if index == 0 else tk.Toplevel(root)
        view = ChatWindow(window, profile, identities[profile], args.data_dir / profile, close_one)
        window.geometry(f"{width}x{height}+{16 + index * (width + 12)}+25")
        windows.append(view)
    if args.demo:
        def connect_demo():
            try:
                port = windows[1].peer.listen("127.0.0.1", 0)
                windows[1].port.set(str(port))
                windows[0].port.set(str(port))
                windows[1].set_connection_state(busy=True)
                windows[0].peer.connect("127.0.0.1", port)
                windows[0].set_connection_state(busy=True)
            except (OSError, ValueError) as exc:
                messagebox.showerror("演示启动失败", str(exc), parent=root)
        root.after(500, connect_demo)
    root.mainloop()
    for view in windows:
        view.peer.close()
        view.peer.wait_closed()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        import traceback
        error = traceback.format_exc()
        print(error, file=sys.stderr)
        Path(__file__).with_name("startup-error.log").write_text(error, encoding="utf-8")
        raise
