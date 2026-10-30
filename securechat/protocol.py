"""Bounded framing, authenticated peer sessions, and streaming file transfer."""

import hashlib
import json
import os
import re
import secrets
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from .crypto import Handshake, Identity, SecurityError, canonical, digest, hex_bytes

MAX_FRAME = 300 * 1024
CHUNK_SIZE = 64 * 1024
MAX_FILE = 2 * 1024**3
MAX_TEXT = 32 * 1024


def receive_exact(sock, size):
    result = bytearray()
    while len(result) < size:
        part = sock.recv(size - len(result))
        if not part:
            raise EOFError("Peer disconnected")
        result.extend(part)
    return bytes(result)


def receive_frame(sock, limit=MAX_FRAME):
    size = struct.unpack("!I", receive_exact(sock, 4))[0]
    if not 1 <= size <= limit:
        raise SecurityError("Frame size limit exceeded")
    return receive_exact(sock, size)


def send_frame(sock, data):
    if not 1 <= len(data) <= MAX_FRAME:
        raise SecurityError("Frame size limit exceeded")
    sock.sendall(struct.pack("!I", len(data)) + data)


def safe_name(name):
    if not isinstance(name, str) or not name or len(name) > 240 or any(ord(c) < 32 for c in name):
        raise SecurityError("Invalid file name")
    base = name.replace("\\", "/").rsplit("/", 1)[-1]
    if (not base or base in (".", "..") or base[-1] in " ." or
            any(c in '<>:"|?*' for c in base) or
            re.fullmatch(r"(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])", base.split(".")[0])):
        raise SecurityError("Unsafe file name")
    return base


class TrustStore:
    def __init__(self, path):
        self.path = Path(path)
        self.lock = threading.Lock()

    def verify(self, name, public, ask):
        fingerprint = digest(hex_bytes(public, 64)).hex()
        with self.lock:
            known = {}
            if self.path.exists():
                if self.path.stat().st_size > 256 * 1024:
                    raise SecurityError("Trust file too large")
                known = json.loads(self.path.read_text(encoding="utf-8"))
                if not isinstance(known, dict):
                    raise SecurityError("Invalid trust file")
            if name in known:
                if known[name] != fingerprint:
                    raise SecurityError("Peer identity changed; inspect the saved trust record")
                return True
            if not ask(name, fingerprint):
                return False
            known[name] = fingerprint
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.path.with_name(self.path.name + ".tmp")
            temporary.write_bytes(canonical(known))
            os.replace(temporary, self.path)
            return True


@dataclass
class Connection:
    sock: object = None
    listener: object = None
    channel: object = None
    stop: threading.Event = field(default_factory=threading.Event)
    send_lock: threading.Lock = field(default_factory=threading.Lock)
    incoming: dict = field(default_factory=dict)
    receipts: dict = field(default_factory=dict)
    receipt_lock: threading.Lock = field(default_factory=threading.Lock)
    remote: str = ""
    ready: bool = False


class Peer:
    def __init__(self, name, identity, directory, notify, ask_trust):
        self.name, self.identity = name, identity
        self.directory = Path(directory)
        self.inbox = self.directory / "received"
        self.inbox.mkdir(parents=True, exist_ok=True)
        self.trust = TrustStore(self.directory / "trusted.json")
        self.notify, self.ask_trust = notify, ask_trust
        self.connection = None
        self.state_lock = threading.Lock()
        self.transfer_lock = threading.Lock()
        self.threads = []

    def emit(self, event_type, **values):
        self.notify({"type": event_type, **values})

    @property
    def connected(self):
        connection = self.connection
        return bool(connection and connection.ready and not connection.stop.is_set())

    def _reserve(self):
        with self.state_lock:
            if self.connection is not None:
                raise ValueError("Already listening, connecting, or connected")
            connection = Connection()
            self.connection = connection
            return connection

    def _start(self, target, *args):
        thread = threading.Thread(target=target, args=args, daemon=True)
        self.threads.append(thread)
        thread.start()

    def listen(self, host, port):
        connection = self._reserve()
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection.listener = listener
        try:
            listener.bind((host, int(port)))
            listener.listen(1)
            listener.settimeout(0.5)
            actual = listener.getsockname()[1]
            self.emit("listening", host=host, port=actual)
            self._start(self._accept, connection)
            return actual
        except Exception:
            listener.close()
            with self.state_lock:
                if self.connection is connection:
                    self.connection = None
            raise

    def _accept(self, connection):
        try:
            while not connection.stop.is_set():
                try:
                    connection.sock, _ = connection.listener.accept()
                    connection.listener.close()
                    self._serve(connection, "server")
                    return
                except socket.timeout:
                    continue
        except (OSError, ValueError, EOFError) as exc:
            if not connection.stop.is_set():
                self.emit("error", message=str(exc))
        finally:
            self._cleanup(connection)

    def connect(self, host, port):
        connection = self._reserve()
        connection.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.emit("connecting", host=host, port=int(port))
        self._start(self._connect, connection, host, int(port))

    def _connect(self, connection, host, port):
        try:
            connection.sock.settimeout(8)
            connection.sock.connect((host, port))
            self._serve(connection, "client")
        except (OSError, ValueError, EOFError) as exc:
            if not connection.stop.is_set():
                self.emit("error", message=str(exc))
        finally:
            self._cleanup(connection)

    def _serve(self, connection, role):
        sock = connection.sock
        sock.settimeout(120)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        handshake = Handshake(self.identity, role, self.name)
        #发送自己的hello
        send_frame(sock, canonical(handshake.hello))
        #接受对方消息 解构成字典
        remote = json.loads(receive_frame(sock, 8192))
        channel = handshake.finish(remote)
        self.emit("handshake", message="SM2 signature verified; X25519 + HKDF-SM3 keys derived")
        connection.remote = remote["name"]
        #核验身份公钥的指纹
        if not self.trust.verify(remote["name"], remote["identity"], self.ask_trust):
            raise SecurityError("Peer fingerprint was not accepted")
        if connection.stop.is_set():
            return
        connection.channel = channel
        challenge = secrets.token_bytes(32)
        encrypted = Identity.encrypt(remote["identity"], challenge)
        self._send(connection, b"J" + canonical({"type": "challenge", "encrypted": encrypted.hex()}))
        probe = channel.open(receive_frame(sock))
        if probe[:1] != b"J":
            raise SecurityError("Invalid SM2 challenge record")
        probe = json.loads(probe[1:])
        if not isinstance(probe, dict) or probe.get("type") != "challenge":
            raise SecurityError("Missing SM2 encrypted challenge")
        decrypted = self.identity.decrypt(hex_bytes(probe.get("encrypted"), 128))
        self._send(connection, b"J" + canonical({"type": "ready", "echo": decrypted.hex()}))
        if channel.open(receive_frame(sock)) != b"J" + canonical({"type": "ready", "echo": challenge.hex()}):
            raise SecurityError("Session key confirmation failed")
        self.emit("asymmetric_verified", message="SM2 encryption challenge and key confirmation passed")
        sock.settimeout(None)
        connection.ready = True
        self.emit("connected", peer=remote["name"],
                  fingerprint=digest(bytes.fromhex(remote["identity"])).hex(), session=channel.session.hex())
        while not connection.stop.is_set():
            plaintext = channel.open(receive_frame(sock))
            self._dispatch(connection, plaintext)

    def _send(self, connection, plaintext):
        with connection.send_lock:
            if connection.stop.is_set() or connection.channel is None:
                raise ConnectionError("Session is closed")
            packet = connection.channel.seal(plaintext)
            try:
                send_frame(connection.sock, packet)
            except OSError:
                connection.stop.set()
                self._shutdown(connection.sock)
                raise
            if plaintext[:1] != b"C":
                self.emit("wire", size=len(packet), preview=packet[:64].hex(),
                          sequence=connection.channel.send_sequence - 1)

    def _current(self):
        connection = self.connection
        if not self.connected or connection is None:
            raise ConnectionError("Connect and verify peer identity first")
        return connection

    def send_text(self, text):
        if not isinstance(text, str) or not text.strip() or len(text.encode("utf-8")) > MAX_TEXT:
            raise ValueError("Text must contain 1 to 32768 UTF-8 bytes")
        connection = self._current()
        self._send(connection, b"J" + canonical({"type": "text", "text": text}))
        self.emit("text_sent", text=text)

    def send_file(self, path, kind="file"):
        if kind not in ("image", "video", "file"):
            raise ValueError("Unknown media kind")
        if not self.transfer_lock.acquire(blocking=False):
            raise ValueError("Another outgoing transfer is active")
        connection = None
        started_transfer = False
        transfer_id = secrets.token_hex(16)
        receipt = {"event": threading.Event(), "ok": False}
        try:
            connection = self._current()
            path = Path(path)
            name = safe_name(path.name)
            with path.open("rb") as stream:
                size = os.fstat(stream.fileno()).st_size
                if not 0 <= size <= MAX_FILE:
                    raise ValueError("File exceeds the 2 GiB limit")
                with connection.receipt_lock:
                    connection.receipts[transfer_id] = receipt
                started_transfer = True
                self._send(connection, b"J" + canonical({"type": "file_start", "id": transfer_id,
                                                        "name": name, "size": size, "kind": kind}))
                hasher = hashlib.new("sm3")
                sent = 0
                started = updated = time.monotonic()
                while block := stream.read(CHUNK_SIZE):
                    sent += len(block)
                    if sent > size:
                        raise ValueError("Source file changed during transfer")
                    hasher.update(block)
                    self._send(connection, b"C" + bytes.fromhex(transfer_id) + block)
                    now = time.monotonic()
                    if now - updated >= 0.1 or sent == size:
                        self.emit("progress", direction="send", name=name, done=sent, total=size)
                        updated = now
                if sent != size:
                    raise ValueError("Source file changed during transfer")
                self._send(connection, b"J" + canonical({"type": "file_end", "id": transfer_id,
                                                        "sm3": hasher.hexdigest()}))
                if not receipt["event"].wait(120) or not receipt["ok"]:
                    raise ConnectionError("Receiver did not acknowledge the verified file")
                self.emit("file_sent", name=name, size=size, kind=kind, sm3=hasher.hexdigest(),
                          seconds=time.monotonic() - started)
        except (OSError, ValueError):
            if started_transfer and connection is not None and not connection.stop.is_set():
                connection.stop.set()
                self._shutdown(connection.sock)
            raise
        finally:
            if connection is not None:
                with connection.receipt_lock:
                    connection.receipts.pop(transfer_id, None)
            self.transfer_lock.release()

    def _dispatch(self, connection, plaintext):
        if plaintext[:1] == b"C":
            if not 17 < len(plaintext) <= 17 + CHUNK_SIZE:
                raise SecurityError("Invalid file block length")
            transfer_id = plaintext[1:17].hex()
            state = connection.incoming.get(transfer_id)
            if state is None or state["done"] + len(plaintext) - 17 > state["size"]:
                raise SecurityError("Unexpected or oversized file block")
            block = plaintext[17:]
            state["stream"].write(block)
            state["hasher"].update(block)
            state["done"] += len(block)
            now = time.monotonic()
            if now - state["updated"] >= 0.1 or state["done"] == state["size"]:
                self.emit("progress", direction="receive", name=state["name"],
                          done=state["done"], total=state["size"])
                state["updated"] = now
            return
        if plaintext[:1] != b"J":
            raise SecurityError("Unknown record format")
        message = json.loads(plaintext[1:])
        if not isinstance(message, dict):
            raise SecurityError("Invalid message")
        kind = message.get("type")
        if kind == "text":
            text = message.get("text")
            if not isinstance(text, str) or not text.strip() or len(text.encode("utf-8")) > MAX_TEXT:
                raise SecurityError("Invalid text message")
            self.emit("text", peer=connection.remote, text=text)
        elif kind in ("file_start", "file_end", "file_ack"):
            transfer_id = hex_bytes(message.get("id"), 16).hex()
            if kind == "file_start":
                self._file_start(connection, transfer_id, message)
            elif kind == "file_end":
                self._file_end(connection, transfer_id, message)
            else:
                with connection.receipt_lock:
                    receipt = connection.receipts.get(transfer_id)
                    if receipt is None:
                        raise SecurityError("Unexpected transfer acknowledgement")
                    receipt["ok"] = True
                    receipt["event"].set()
        else:
            raise SecurityError("Unknown message type")

    def _file_start(self, connection, transfer_id, message):
        if transfer_id in connection.incoming or len(connection.incoming) >= 4:
            raise SecurityError("Duplicate or excessive file transfers")
        name = safe_name(message.get("name"))
        size = message.get("size")
        if type(size) is not int or not 0 <= size <= MAX_FILE or message.get("kind") not in ("image", "video", "file"):
            raise SecurityError("Invalid file metadata")
        temporary = self.inbox / (".partial-" + transfer_id)
        stream = temporary.open("xb")
        connection.incoming[transfer_id] = {
            "name": name, "size": size, "kind": message["kind"], "stream": stream,
            "temporary": temporary, "hasher": hashlib.new("sm3"), "done": 0,
            "started": time.monotonic(), "updated": 0,
        }
        self.emit("progress", direction="receive", name=name, done=0, total=size)

    def _file_end(self, connection, transfer_id, message):
        state = connection.incoming.get(transfer_id)
        if state is None:
            raise SecurityError("Unexpected file completion")
        expected = hex_bytes(message.get("sm3"), 32).hex()
        if state["done"] != state["size"] or state["hasher"].hexdigest() != expected:
            raise SecurityError("File size or SM3 digest mismatch")
        state["stream"].flush()
        os.fsync(state["stream"].fileno())
        state["stream"].close()
        original = Path(state["name"])
        for suffix in range(10000):
            name = original.name if suffix == 0 else f"{original.stem} ({suffix}){original.suffix}"
            destination = self.inbox / name
            try:
                reserved = destination.open("xb")
            except FileExistsError:
                continue
            reserved.close()
            try:
                os.replace(state["temporary"], destination)
            except OSError:
                destination.unlink(missing_ok=True)
                raise
            break
        else:
            raise SecurityError("Too many duplicate file names")
        del connection.incoming[transfer_id]
        self._send(connection, b"J" + canonical({"type": "file_ack", "id": transfer_id}))
        self.emit("file_received", path=str(destination), name=destination.name,
                  kind=state["kind"], size=state["size"], sm3=expected,
                  seconds=time.monotonic() - state["started"])

    @staticmethod
    def _shutdown(sock):
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()

    def close(self):
        connection = self.connection
        if connection is not None:
            connection.stop.set()
            self._shutdown(connection.sock)
            self._shutdown(connection.listener)

    def _cleanup(self, connection):
        connection.stop.set()
        connection.ready = False
        self._shutdown(connection.sock)
        self._shutdown(connection.listener)
        for state in connection.incoming.values():
            state["stream"].close()
            state["temporary"].unlink(missing_ok=True)
        connection.incoming.clear()
        with connection.receipt_lock:
            for receipt in connection.receipts.values():
                receipt["event"].set()
        connection.channel = None
        with self.state_lock:
            if self.connection is connection:
                self.connection = None
        self.emit("disconnected")

    def wait_closed(self, timeout=3):
        deadline = time.monotonic() + timeout
        for thread in self.threads:
            thread.join(max(0, deadline - time.monotonic()))
