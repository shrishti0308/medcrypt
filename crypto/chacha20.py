from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20
import os


class ChaCha20Cipher:
    def __init__(self):
        """Initialize ChaCha20 cipher"""
        pass

    def encrypt(self, data, key):
        """
        Encrypt data using ChaCha20.
        Returns (nonce, ciphertext)
        """
        if isinstance(data, str):
            data = data.encode()

        # Generate random nonce
        nonce = os.urandom(16)

        # Single-pass encryption using optimized ChaCha20
        algorithm = ChaCha20(key, nonce)
        cipher = Cipher(algorithm, mode=None).encryptor()
        ciphertext = cipher.update(data)  # ChaCha20 is already single-pass

        return nonce, ciphertext

    def decrypt(self, nonce, ciphertext, key):
        """Decrypt data using ChaCha20"""
        # Single-pass decryption
        algorithm = ChaCha20(key, nonce)
        cipher = Cipher(algorithm, mode=None).decryptor()
        plaintext = cipher.update(ciphertext)

        return plaintext
