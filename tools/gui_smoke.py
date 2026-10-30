"""Exercise the actual Tk views over loopback without touching user identities."""

import argparse
import json
import sys
import tempfile
import time
import tkinter as tk
from pathlib import Path

from PIL import ImageGrab

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from securechat.crypto import Identity
from securechat.gui import ChatWindow, configure_style


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--hold", type=int, default=0)
    args = parser.parse_args()
    report = {}
    with tempfile.TemporaryDirectory() as temporary:
        root = tk.Tk()
        configure_style(root)
        a = ChatWindow(root, "Alice", Identity.generate(), Path(temporary) / "Alice")
        b = ChatWindow(tk.Toplevel(root), "Bob", Identity.generate(), Path(temporary) / "Bob")
        root.geometry("800x860+20+20")
        b.window.geometry("800x860+840+20")
        # This isolated harness accepts only the two identities it just generated.
        a.peer.ask_trust = lambda name, fp: name == "Bob" and fp == b.identity.fingerprint
        b.peer.ask_trust = lambda name, fp: name == "Alice" and fp == a.identity.fingerprint

        def pump(predicate, timeout=10):
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                root.update()
                if predicate():
                    return
                time.sleep(0.02)
            raise AssertionError("GUI operation timed out")

        try:
            port = b.peer.listen("127.0.0.1", 0)
            a.port.set(str(port))
            b.port.set(str(port))
            a.peer.connect("127.0.0.1", port)
            pump(lambda: a.connected and b.connected)
            report["connected"] = True
            a.composer.insert("1.0", "你好，Bob！这是一条加密消息。")
            a.send_text()
            pump(lambda: "你好，Bob" in b.chat.get("1.0", "end"))
            b.composer.insert("1.0", "Alice，消息已收到，开始传输图片与视频。")
            b.send_text()
            pump(lambda: "消息已收到" in a.chat.get("1.0", "end"))
            report["bidirectional_text"] = True
            for name, kind in (("sample-image.png", "image"), ("sample-video.mp4", "video")):
                source = ROOT / "samples" / name
                before = len(b.received)
                a.send_file(source, kind)
                pump(lambda: len(b.received) > before and not a.send_busy, timeout=20)
                received = b.received[-1]
                assert Path(received["path"]).read_bytes() == source.read_bytes()
                report[kind] = {"bytes": received["size"], "sm3": received["sm3"]}
            assert b.images, "Image preview did not render"
            report["image_preview"] = True
            a.run_lab()
            pump(lambda: "重复记录：已拒绝" in a.lab_log.get("1.0", "end"))
            report["tamper_replay_demo"] = True
            root.update()
            report["layout"] = []
            for view in (a, b):
                record = {"name": view.name, "window_width": view.window.winfo_width(),
                          "required_width": view.window.winfo_reqwidth(), "overflows": []}
                def inspect(widget):
                    for child in widget.winfo_children():
                        if isinstance(child, tk.Toplevel):
                            continue
                        if child.winfo_ismapped():
                            right = child.winfo_x() + child.winfo_width()
                            bottom = child.winfo_y() + child.winfo_height()
                            if right > widget.winfo_width() + 2 or bottom > widget.winfo_height() + 2:
                                record["overflows"].append(str(child))
                            inspect(child)
                inspect(view.window)
                report["layout"].append(record)
            output = ROOT / "output" / "evidence"
            output.mkdir(parents=True, exist_ok=True)
            for view, filename in ((a, "alice-chat.png"), (b, "bob-chat.png")):
                view.window.lift()
                root.update()
                ImageGrab.grab(window=view.window.winfo_id()).save(output / filename)
            a.notebook.select(1)
            root.update()
            ImageGrab.grab(window=root.winfo_id()).save(output / "session.png")
            a.notebook.select(2)
            root.update()
            ImageGrab.grab(window=root.winfo_id()).save(output / "security-lab.png")
            a.notebook.select(0)
            root.update()
            root.geometry("680x700")
            root.update()
            small_overflows = []
            def check_small(widget):
                for child in widget.winfo_children():
                    if isinstance(child, tk.Toplevel) or not child.winfo_ismapped():
                        continue
                    if child.winfo_x() + child.winfo_width() > widget.winfo_width() + 2:
                        small_overflows.append(str(child))
                    check_small(child)
            check_small(root)
            assert not small_overflows, f"Small window overflow: {small_overflows}"
            report["small_window_layout"] = True
            a.peer.close()
            pump(lambda: a.peer.connection is None and not a.connected)
            a.set_connection_state(busy=True, connected=True)
            a.composer.insert("1.0", "断开瞬间的消息草稿")
            before = a.lab_log.get("1.0", "end")
            a.send_text()
            pump(lambda: a.lab_log.get("1.0", "end") != before)
            assert a.composer.get("1.0", "end-1c") == "断开瞬间的消息草稿", "Failed send discarded draft"
            report["failed_send_preserves_draft"] = True
            (output / "gui-smoke.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
            print(json.dumps(report, ensure_ascii=False, indent=2), flush=True)
            until = time.monotonic() + args.hold
            while time.monotonic() < until:
                root.update()
                time.sleep(0.05)
        finally:
            for view in (a, b):
                if not view.closed:
                    view.closed = True
                    view.window.after_cancel(view.poll_id)
                view.peer.close()
            for view in (a, b):
                view.peer.wait_closed()
            root.destroy()


if __name__ == "__main__":
    main()
