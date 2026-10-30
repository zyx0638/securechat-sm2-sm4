import copy
import tempfile
import unittest
from pathlib import Path

from securechat.crypto import Channel, Handshake, Identity, SecurityError, digest


class CryptoTests(unittest.TestCase):
    def setUp(self):
        self.alice = Identity.generate()
        self.bob = Identity.generate()

    def channels(self):
        a = Handshake(self.alice, "client")
        b = Handshake(self.bob, "server")
        return a.finish(b.hello), b.finish(a.hello)

    def test_sm3_standard_vector(self):
        self.assertEqual(digest(b"abc").hex(),
                         "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0")

    def test_sm2_signature_rejects_changed_message(self):
        sig = self.alice.sign(b"message")
        self.assertTrue(Identity.verify(self.alice.public, b"message", sig))
        self.assertFalse(Identity.verify(self.alice.public, b"changed", sig))
        self.assertFalse(Identity.verify(self.bob.public, b"message", sig))

    def test_sm2_public_key_encryption_and_ciphertext_integrity(self):
        message = bytes(range(32))
        ciphertext = Identity.encrypt(self.bob.public, message)
        self.assertNotIn(message, ciphertext)
        self.assertEqual(self.bob.decrypt(ciphertext), message)
        self.assertNotEqual(Identity.encrypt(self.bob.public, message), ciphertext)
        with self.assertRaises(SecurityError):
            self.alice.decrypt(ciphertext)
        damaged = bytearray(ciphertext)
        damaged[70] ^= 1
        with self.assertRaises(SecurityError):
            self.bob.decrypt(bytes(damaged))
        with self.assertRaises(SecurityError):
            Identity.encrypt("00" * 64, message)

    def test_private_key_encrypted_and_wrong_password_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "identity.json"
            self.alice.save(path, "correct horse battery")
            self.assertNotIn(self.alice.private, path.read_text())
            self.assertEqual(Identity.load(path, "correct horse battery").public, self.alice.public)
            with self.assertRaises(SecurityError):
                Identity.load(path, "wrong password")

    def test_handshake_rejects_tampered_share_and_reflected_role(self):
        a = Handshake(self.alice, "client")
        b = Handshake(self.bob, "server")
        bad = copy.deepcopy(b.hello)
        bad["ephemeral"] = "00" * 32
        with self.assertRaises(SecurityError):
            a.finish(bad)
        with self.assertRaises(SecurityError):
            a.finish(a.hello)

    def test_bidirectional_records_and_no_plaintext_on_wire(self):
        a, b = self.channels()
        packet = a.seal(b"hello secret")
        self.assertNotIn(b"hello secret", packet)
        self.assertEqual(b.open(packet), b"hello secret")
        self.assertEqual(a.open(b.seal(b"reply")), b"reply")
        with self.assertRaises(SecurityError):
            a.open(packet)

    def test_tamper_replay_and_cross_session_rejected(self):
        a, b = self.channels()
        packet = a.seal(b"payload")
        corrupted = bytearray(packet)
        corrupted[-40] ^= 1
        with self.assertRaises(SecurityError):
            b.open(bytes(corrupted))
        self.assertEqual(b.open(packet), b"payload")
        with self.assertRaises(SecurityError):
            b.open(packet)
        _, other = self.channels()
        with self.assertRaises(SecurityError):
            other.open(packet)

    def test_out_of_order_and_truncated_records_rejected(self):
        a, b = self.channels()
        first, second = a.seal(b"first"), a.seal(b"second")
        with self.assertRaises(SecurityError):
            b.open(second)
        with self.assertRaises(SecurityError):
            b.open(first[:20])
        self.assertEqual(b.open(first), b"first")
        self.assertEqual(b.open(second), b"second")


if __name__ == "__main__":
    unittest.main()
