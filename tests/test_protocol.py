import json
import queue
import socket
import struct
import tempfile
import time
import unittest
from pathlib import Path

from securechat.crypto import Handshake, Identity, SecurityError, canonical
from securechat.protocol import MAX_FRAME, Peer, TrustStore, receive_frame, safe_name, send_frame


def wait_event(events, kind, timeout=8):
    deadline = time.monotonic() + timeout
    seen = []
    while time.monotonic() < deadline:
        item = events.get(timeout=max(0.01, deadline - time.monotonic()))
        seen.append(item)
        if item["type"] == kind:
            return item
    raise AssertionError(f"Missing {kind}; events: {seen}")


class ProtocolTests(unittest.TestCase):
    def test_frame_length_bound_and_fragmented_input(self):
        a, b = socket.socketpair()
        try:
            a.sendall(struct.pack("!I", 5)[:2])
            a.sendall(struct.pack("!I", 5)[2:] + b"hello")
            self.assertEqual(receive_frame(b), b"hello")
            a.sendall(struct.pack("!I", MAX_FRAME + 1))
            with self.assertRaises(SecurityError):
                receive_frame(b)
        finally:
            a.close()
            b.close()

    def test_safe_filename_never_escapes_directory(self):
        self.assertEqual(safe_name("../../outside.mp4"), "outside.mp4")
        self.assertEqual(safe_name("C:\\secret\\photo.png"), "photo.png")
        for value in ["CON", "aux.txt", "..", "", "NUL.mp4", "x\x00y"]:
            with self.subTest(value=value), self.assertRaises(SecurityError):
                safe_name(value)

    def test_trust_change_is_rejected_without_reprompt(self):
        with tempfile.TemporaryDirectory() as directory:
            store = TrustStore(Path(directory) / "trusted.json")
            a, b = Identity.generate(), Identity.generate()
            self.assertTrue(store.verify("Bob", a.public, lambda *args: True))
            reloaded = TrustStore(Path(directory) / "trusted.json")
            with self.assertRaises(SecurityError):
                reloaded.verify("Bob", b.public, lambda *args: self.fail("Changed identity was prompted"))

    def test_rejected_identity_never_connects(self):
        with tempfile.TemporaryDirectory() as directory:
            events = queue.Queue()
            a = Peer("Alice", Identity.generate(), Path(directory) / "a", events.put, lambda *args: False)
            b = Peer("Bob", Identity.generate(), Path(directory) / "b", lambda e: None, lambda *args: True)
            try:
                port = b.listen("127.0.0.1", 0)
                a.connect("127.0.0.1", port)
                wait_event(events, "error")
                self.assertFalse(a.connected)
            finally:
                a.close()
                b.close()
                a.wait_closed()
                b.wait_closed()

    def test_real_tcp_text_binary_empty_and_duplicate_filename(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            aq, bq = queue.Queue(), queue.Queue()
            a = Peer("Alice", Identity.generate(), folder / "a", aq.put, lambda *args: True)
            b = Peer("Bob", Identity.generate(), folder / "b", bq.put, lambda *args: True)
            try:
                a.connect("127.0.0.1", b.listen("127.0.0.1", 0))
                wait_event(aq, "connected")
                wait_event(bq, "connected")
                a.send_text("你好，安全通信！")
                self.assertEqual(wait_event(bq, "text")["text"], "你好，安全通信！")
                b.send_text("双向回复")
                self.assertEqual(wait_event(aq, "text")["text"], "双向回复")
                with self.assertRaises(OSError):
                    a.send_file(folder / "missing.mp4", "video")
                a.send_text("选择文件失败后会话仍然有效")
                self.assertEqual(wait_event(bq, "text")["text"], "选择文件失败后会话仍然有效")
                source = folder / "clip.mp4"
                content = bytes(range(256)) * 1024 + b"tail"
                source.write_bytes(content)
                a.send_file(source, "video")
                first = wait_event(bq, "file_received")
                self.assertEqual(Path(first["path"]).read_bytes(), content)
                a.send_file(source, "video")
                second = wait_event(bq, "file_received")
                self.assertNotEqual(first["path"], second["path"])
                self.assertEqual(Path(first["path"]).read_bytes(), content)
                empty = folder / "empty.dat"
                empty.write_bytes(b"")
                b.send_file(empty, "file")
                self.assertEqual(Path(wait_event(aq, "file_received")["path"]).read_bytes(), b"")
                with self.assertRaises(ValueError):
                    a.send_text("x" * 40000)
            finally:
                a.close()
                b.close()
                a.wait_closed()
                b.wait_closed()

    def test_bad_file_digest_disconnects_and_removes_partial_file(self):
        with tempfile.TemporaryDirectory() as directory:
            aq, bq = queue.Queue(), queue.Queue()
            a = Peer("Alice", Identity.generate(), Path(directory) / "a", aq.put, lambda *args: True)
            b = Peer("Bob", Identity.generate(), Path(directory) / "b", bq.put, lambda *args: True)
            try:
                a.connect("127.0.0.1", b.listen("127.0.0.1", 0))
                wait_event(aq, "connected")
                wait_event(bq, "connected")
                transfer = "12" * 16
                a._send(a.connection, b"J" + canonical({"type": "file_start", "id": transfer,
                                                       "name": "wrong.png", "size": 3, "kind": "image"}))
                a._send(a.connection, b"C" + bytes.fromhex(transfer) + b"abc")
                a._send(a.connection, b"J" + canonical({"type": "file_end", "id": transfer, "sm3": "00" * 32}))
                self.assertIn("digest", wait_event(bq, "error")["message"])
                wait_event(bq, "disconnected")
                self.assertEqual(list(b.inbox.iterdir()), [])
            finally:
                a.close()
                b.close()
                a.wait_closed()
                b.wait_closed()

    def test_disconnect_cleans_incomplete_transfer(self):
        with tempfile.TemporaryDirectory() as directory:
            aq, bq = queue.Queue(), queue.Queue()
            a = Peer("Alice", Identity.generate(), Path(directory) / "a", aq.put, lambda *args: True)
            b = Peer("Bob", Identity.generate(), Path(directory) / "b", bq.put, lambda *args: True)
            try:
                a.connect("127.0.0.1", b.listen("127.0.0.1", 0))
                wait_event(aq, "connected")
                wait_event(bq, "connected")
                a._send(a.connection, b"J" + canonical({"type": "file_start", "id": "34" * 16,
                                                       "name": "partial.mp4", "size": 100, "kind": "video"}))
                wait_event(bq, "progress")
                a.close()
                wait_event(bq, "disconnected")
                self.assertEqual(list(b.inbox.iterdir()), [])
            finally:
                a.close()
                b.close()
                a.wait_closed()
                b.wait_closed()

    def test_wrong_sm2_challenge_echo_never_connects(self):
        with tempfile.TemporaryDirectory() as directory:
            events = queue.Queue()
            b = Peer("Bob", Identity.generate(), Path(directory) / "b", events.put, lambda *args: True)
            client = socket.socket()
            client.settimeout(5)
            try:
                client.connect(("127.0.0.1", b.listen("127.0.0.1", 0)))
                handshake = Handshake(Identity.generate(), "client", "Alice")
                send_frame(client, canonical(handshake.hello))
                remote = json.loads(receive_frame(client))
                channel = handshake.finish(remote)
                channel.open(receive_frame(client))
                challenge = Identity.encrypt(b.identity.public, b"a" * 32)
                send_frame(client, channel.seal(b"J" + canonical({"type": "challenge", "encrypted": challenge.hex()})))
                channel.open(receive_frame(client))
                send_frame(client, channel.seal(b"J" + canonical({"type": "ready", "echo": "00" * 32})))
                self.assertIn("confirmation failed", wait_event(events, "error")["message"])
                self.assertFalse(b.connected)
            finally:
                client.close()
                b.close()
                b.wait_closed()


if __name__ == "__main__":
    unittest.main()
