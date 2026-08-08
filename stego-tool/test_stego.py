"""
test_stego.py
Minimal unit tests -- run with: python3 -m unittest test_stego.py -v
No pytest dependency required, keeps the project stdlib-light like the
other portfolio tools (HashCrack, Honeypot Listener, etc.).
"""

import os
import unittest
from PIL import Image

import stego
import utils
import crypto_layer


class TestUtils(unittest.TestCase):
    def test_bytes_to_bits_and_back(self):
        data = b"Hello, World!"
        bits = utils.bytes_to_bits(data)
        self.assertEqual(len(bits), len(data) * 8)
        self.assertEqual(utils.bits_to_bytes(bits), data)

    def test_capacity_math(self):
        # 10x10 image, 3 channels = 300 bits available, minus 32-bit header
        cap = utils.calculate_capacity_bytes(10, 10, channels=3, header_bits=32)
        self.assertEqual(cap, (300 - 32) // 8)


class TestStegoRoundTrip(unittest.TestCase):
    def setUp(self):
        self.cover_path = "test_cover_tmp.png"
        self.stego_path = "test_stego_tmp.png"
        img = Image.new("RGB", (50, 50), color=(120, 130, 140))
        img.save(self.cover_path)

    def tearDown(self):
        for path in (self.cover_path, self.stego_path):
            if os.path.exists(path):
                os.remove(path)

    def test_encode_decode_round_trip(self):
        message = b"secret payload 123"
        stego.encode(self.cover_path, self.stego_path, message)
        recovered = stego.decode(self.stego_path)
        self.assertEqual(recovered, message)

    def test_capacity_overflow_raises(self):
        huge_message = b"x" * 100_000  # way bigger than a 50x50 image can hold
        with self.assertRaises(stego.StegoError):
            stego.encode(self.cover_path, self.stego_path, huge_message)

    def test_decode_untouched_image_raises_or_garbage(self):
        # An image with no embedded header will almost certainly decode to
        # a garbage / huge length and raise, rather than returning valid data.
        with self.assertRaises((stego.StegoError, ValueError, MemoryError)):
            stego.decode(self.cover_path)


class TestCryptoLayer(unittest.TestCase):
    def test_encrypt_decrypt_round_trip(self):
        message = b"top secret"
        password = "correct-horse-battery-staple"
        encrypted = crypto_layer.encrypt(message, password)
        decrypted = crypto_layer.decrypt(encrypted, password)
        self.assertEqual(decrypted, message)

    def test_wrong_password_fails(self):
        message = b"top secret"
        encrypted = crypto_layer.encrypt(message, "right-password")
        with self.assertRaises(crypto_layer.CryptoError):
            crypto_layer.decrypt(encrypted, "wrong-password")


if __name__ == "__main__":
    unittest.main()
