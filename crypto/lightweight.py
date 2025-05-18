from .ecc import ECCCipher
from .chacha20 import ChaCha20Cipher


class LightweightCrypto:
    def __init__(self):
        """Initialize lightweight cryptography system using ECC and ChaCha20"""
        self.ecc = ECCCipher()
        self.chacha20 = ChaCha20Cipher()

    def encrypt(self, data, ecc_public_key_path):
        """
        Encrypt data using lightweight hybrid encryption:
        1. Use ECDH to establish a shared secret
        2. Derive ChaCha20 key from shared secret
        3. Encrypt data with ChaCha20
        4. Return encrypted data and necessary key material
        """
        # Load ECC public key
        public_key = self.ecc.load_public_key(ecc_public_key_path)

        # Get shared secret and encryption key using ECC
        ephemeral_public, encryption_key = self.ecc.encrypt(data, public_key)

        # Encrypt data with ChaCha20
        nonce, encrypted_data = self.chacha20.encrypt(data, encryption_key)

        # Combine ephemeral public key and nonce for transmission
        key_material = ephemeral_public + nonce

        return encrypted_data, key_material

    def decrypt(self, encrypted_data, key_material, ecc_private_key_path):
        """
        Decrypt data using lightweight hybrid decryption:
        1. Extract ephemeral public key and nonce
        2. Use ECDH to recover shared secret
        3. Derive ChaCha20 key
        4. Decrypt data with ChaCha20
        """
        # Load ECC private key
        private_key = self.ecc.load_private_key(ecc_private_key_path)

        # Split key material into components
        ephemeral_public = key_material[:-16]  # All but last 16 bytes
        nonce = key_material[-16:]  # Last 16 bytes

        # Get decryption key using ECC
        decryption_key = self.ecc.decrypt(ephemeral_public, private_key)

        # Decrypt data with ChaCha20
        decrypted_data = self.chacha20.decrypt(nonce, encrypted_data, decryption_key)

        return decrypted_data
