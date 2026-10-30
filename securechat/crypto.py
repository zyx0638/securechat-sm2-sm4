"""Library-backed cryptographic building blocks for the teaching protocol."""

import hashlib
import hmac
import json
import os
import secrets
import struct
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from gmssl import func as gmfunc, sm2

DOMAIN = b"SecureChat-Lab-v1\x00"
ORDER = int(sm2.default_ecc_table["n"], 16)
MAX_PLAINTEXT = 256 * 1024


def secure_random_hex(length):
    if length == 64:
        return f"{secrets.randbelow(ORDER - 1) + 1:064x}"
    return secrets.token_hex((length + 1) // 2)[:length]


# gmssl's default uses random.choice; SM2 encryption needs an OS-backed nonce.
gmfunc.random_hex = secure_random_hex


class SecurityError(ValueError):
    """An untrusted input failed a security check."""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def digest(data):
    return hashlib.new("sm3", data).digest()


def hex_bytes(value, length):
    if not isinstance(value, str) or len(value) != length * 2:
        raise SecurityError("Invalid encoded field length")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise SecurityError("Invalid hexadecimal field") from exc


def sm2_engine(private="", public=""):
    engine = sm2.CryptSM2(private_key=private, public_key=public)
    # gmssl 3.2.2 uses lstrip('04'); preserve a raw coordinate starting in 0/4.
    engine.public_key = public
    return engine


def validate_sm2_point(public):
    raw = hex_bytes(public, 64)
    x, y = int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
    curve = sm2.default_ecc_table
    p, a, b = (int(curve[k], 16) for k in ("p", "a", "b"))
    if not (0 <= x < p and 0 <= y < p and (y * y - x * x * x - a * x - b) % p == 0):
        raise SecurityError("Invalid SM2 curve point")


class Identity:
    def __init__(self, private, public):
        self.private = private
        self.public = public

    @classmethod
    def generate(cls):
        private = f"{secrets.randbelow(ORDER - 2) + 1:064x}"
        public = sm2_engine()._kg(int(private, 16), sm2.default_ecc_table["g"])
        return cls(private, public)

    @property
    def fingerprint(self):
        return digest(bytes.fromhex(self.public)).hex()

    def sign(self, message):
        engine = sm2_engine(self.private, self.public)
        for _ in range(16):
            nonce = f"{secrets.randbelow(ORDER - 1) + 1:064x}"
            signature = engine.sign_with_sm3(message, nonce)
            if signature:
                return signature
        raise SecurityError("SM2 signature generation failed")

    @staticmethod
    def verify(public, message, signature):
        try:
            validate_sm2_point(public)
            raw = hex_bytes(signature, 64)
            if not all(1 <= int.from_bytes(v, "big") < ORDER for v in (raw[:32], raw[32:])):
                return False
            return bool(sm2_engine(public=public).verify_with_sm3(signature, message))
        except (ValueError, TypeError, IndexError, ZeroDivisionError):
            return False

    @staticmethod
    def encrypt(public, plaintext):
        validate_sm2_point(public)
        if not 1 <= len(plaintext) <= 1024:
            raise SecurityError("SM2 is limited to small nonempty envelopes")
        engine = sm2_engine(public=public)
        engine.mode = 1
        for _ in range(16):
            result = engine.encrypt(plaintext)
            if result:
                return result
        raise SecurityError("SM2 encryption failed")

    def decrypt(self, ciphertext):
        if not 97 <= len(ciphertext) <= 1120:
            raise SecurityError("Invalid SM2 envelope length")
        point = ciphertext[:64].hex()
        validate_sm2_point(point)
        engine = sm2_engine(self.private, self.public)
        engine.mode = 1
        try:
            plaintext = engine.decrypt(ciphertext)
            shared = bytes.fromhex(engine._kg(int(self.private, 16), point))
            # gmssl 3.2.2 computes C3 but does not compare it on decrypt.
            expected = digest(shared[:32] + plaintext + shared[32:])
            if not hmac.compare_digest(expected, ciphertext[64:96]):
                raise SecurityError("SM2 C3 digest verification failed")
            return plaintext
        except (TypeError, ValueError) as exc:
            raise SecurityError("SM2 envelope rejected") from exc

    def save(self, path, password):
        if len(password) < 8:
            raise SecurityError("Identity password must have at least 8 characters")
        salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
        key = Scrypt(salt=salt, length=32, n=32768, r=8, p=1).derive(password.encode("utf-8"))
        encrypted = AESGCM(key).encrypt(nonce, bytes.fromhex(self.private), DOMAIN + bytes.fromhex(self.public))
        data = {"version": 1, "public": self.public, "salt": salt.hex(), "nonce": nonce.hex(),
                "encrypted": encrypted.hex()}
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(path.name + "." + secrets.token_hex(8) + ".tmp")
        try:
            with temporary.open("xb") as stream:
                stream.write(canonical(data))
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)

    @classmethod
    def load(cls, path, password):
        try:
            path = Path(path)
            if path.stat().st_size > 4096:
                raise SecurityError("Identity file too large")
            data = json.loads(path.read_text(encoding="utf-8"))
            if data["version"] != 1:
                raise SecurityError("Unsupported identity version")
            public = hex_bytes(data["public"], 64).hex()
            salt, nonce = hex_bytes(data["salt"], 16), hex_bytes(data["nonce"], 12)
            encrypted = hex_bytes(data["encrypted"], 48)
            key = Scrypt(salt=salt, length=32, n=32768, r=8, p=1).derive(password.encode("utf-8"))
            private = AESGCM(key).decrypt(nonce, encrypted, DOMAIN + bytes.fromhex(public)).hex()
            if not 1 <= int(private, 16) <= ORDER - 2:
                raise SecurityError("Invalid identity scalar")
            expected = sm2_engine()._kg(int(private, 16), sm2.default_ecc_table["g"])
            if not hmac.compare_digest(expected, public):
                raise SecurityError("Identity key mismatch")
            return cls(private, public)
        except (InvalidTag, KeyError, TypeError, ValueError, UnicodeError) as exc:
            raise SecurityError("Wrong password or damaged identity file") from exc


class Handshake:
    def __init__(self, identity, role, name="Peer"):
        if role not in ("client", "server") or not isinstance(name, str) or not 1 <= len(name) <= 64:
            raise ValueError("Invalid role or peer name")
        self.role = role
        #生成临时密钥
        self.private = X25519PrivateKey.generate()
        public = self.private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        #准备并签名hello
        self.hello = {"version": 1, "role": role, "name": name, "identity": identity.public,
                      "ephemeral": public.hex(), "nonce": secrets.token_hex(32)}
        self.hello["signature"] = identity.sign(DOMAIN + canonical(self.hello))

    @staticmethod
    def validate(hello, expected_role):
        try:
            if not isinstance(hello, dict) or set(hello) != {
                "version", "role", "name", "identity", "ephemeral", "nonce", "signature"
            }:
                raise SecurityError("Invalid handshake fields")
            if hello["version"] != 1 or hello["role"] != expected_role:
                raise SecurityError("Handshake version or role mismatch")
            if not isinstance(hello["name"], str) or not 1 <= len(hello["name"]) <= 64:
                raise SecurityError("Invalid peer name")
            hex_bytes(hello["ephemeral"], 32)
            hex_bytes(hello["nonce"], 32)
            payload = {k: v for k, v in hello.items() if k != "signature"}
            if not Identity.verify(hello["identity"], DOMAIN + canonical(payload), hello["signature"]):
                raise SecurityError("SM2 identity signature rejected")
        except (KeyError, TypeError, UnicodeError) as exc:
            raise SecurityError("Malformed handshake") from exc

    def finish(self, remote):
        self.validate(remote, "server" if self.role == "client" else "client")
        client, server = (self.hello, remote) if self.role == "client" else (remote, self.hello)
        session = digest(DOMAIN + canonical([client, server]))
        try:
            #X25519 用自己的临时私钥和对方的临时公钥，算出共享秘密。
            shared = self.private.exchange(X25519PublicKey.from_public_bytes(bytes.fromhex(remote["ephemeral"])))
        except ValueError as exc:
            raise SecurityError("Invalid X25519 public key") from exc
        #HKDF-SM3 计算出程序需要的密钥材料
        material = HKDF(algorithm=hashes.SM3(), length=96, salt=session,
                        info=DOMAIN + b"directional traffic keys").derive(shared)
        c2s, s2c = material[:48], material[48:]
        send, receive = (c2s, s2c) if self.role == "client" else (s2c, c2s)
        return Channel(send, receive, session)


class Channel:
    def __init__(self, send_key, receive_key, session):
        self.send_key = send_key
        self.receive_key = receive_key
        self.session = session
        self.send_sequence = 0
        self.receive_sequence = 0
    #sm4加密
    def seal(self, plaintext):
        if len(plaintext) > MAX_PLAINTEXT or self.send_sequence >= 2**64:
            raise SecurityError("Record size or sequence limit exceeded")
        #IV（初始化向量）每条消息重新随机生成，让同一密钥下重复发送的“你好”也能产生不同密文。
        iv = secrets.token_bytes(16)
        #填充
        padder = padding.PKCS7(128).padder()
        padded = padder.update(plaintext) + padder.finalize()
        encryptor = Cipher(algorithms.SM4(self.send_key[:16]), modes.CBC(iv)).encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()
        body = struct.pack("!Q", self.send_sequence) + iv + ciphertext
        #HMAC-SM3 计算认证值tag 用于验证消息是否被篡改
        tag = hmac.digest(self.send_key[16:], DOMAIN + self.session + body, "sm3")
        self.send_sequence += 1
        return body + tag

    def open(self, packet):
        if not 72 <= len(packet) <= MAX_PLAINTEXT + 88 or (len(packet) - 56) % 16:
            raise SecurityError("Invalid encrypted record length")
        body, received = packet[:-32], packet[-32:]
        expected = hmac.digest(self.receive_key[16:], DOMAIN + self.session + body, "sm3")
        if not hmac.compare_digest(received, expected):
            raise SecurityError("HMAC-SM3 verification failed: modified record")
        sequence = struct.unpack("!Q", body[:8])[0]
        if sequence != self.receive_sequence:
            raise SecurityError("Sequence rejected: replay or out-of-order record")
        decryptor = Cipher(algorithms.SM4(self.receive_key[:16]), modes.CBC(body[8:24])).decryptor()
        padded = decryptor.update(body[24:]) + decryptor.finalize()
        try:
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded) + unpadder.finalize()
        except ValueError as exc:
            raise SecurityError("Invalid encrypted padding") from exc
        self.receive_sequence += 1
        return plaintext


def security_demo():
    alice, bob = Identity.generate(), Identity.generate()
    left, right = Handshake(alice, "client"), Handshake(bob, "server")
    sender, receiver = left.finish(right.hello), right.finish(left.hello)
    packet = sender.seal(b"Tamper and replay laboratory")
    modified = bytearray(packet)
    modified[30] ^= 1
    result = {"ciphertext": packet.hex(), "tamper_rejected": False, "replay_rejected": False}
    try:
        receiver.open(bytes(modified))
    except SecurityError:
        result["tamper_rejected"] = True
    receiver.open(packet)
    try:
        receiver.open(packet)
    except SecurityError:
        result["replay_rejected"] = True
    return result
