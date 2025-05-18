from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class ECCCipher:
    def __init__(self):
        """Initialize ECC cipher"""
        self._curve = ec.SECP256K1()  # Cache curve instance
        self._context = None  # Cache context for faster operations

    def generate_key_pair(self):
        """Generate a new ECC key pair"""
        private_key = ec.generate_private_key(self._curve)
        public_key = private_key.public_key()
        return private_key, public_key

    def save_keys(self, private_key, public_key, private_path, public_path):
        """Save keys to files"""
        # Save private key
        with open(private_path, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

        # Save public key
        with open(public_path, "wb") as f:
            f.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )

    def load_public_key(self, path):
        """Load public key from file"""
        with open(path, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise ValueError("Loaded key is not an ECC public key")
        return public_key

    def load_private_key(self, path):
        """Load private key from file"""
        with open(path, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        if not isinstance(private_key, ec.EllipticCurvePrivateKey):
            raise ValueError("Loaded key is not an ECC private key")
        return private_key

    def derive_key(self, shared_key, salt=None):
        """Derive encryption key from shared secret using HKDF"""
        if salt is None:
            salt = b"\x00" * 32

        # Use HKDF to derive a key
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit key
            salt=salt,
            info=b"ChaCha20 key derivation",
        ).derive(shared_key)

        return derived_key

    def encrypt(self, data, public_key):
        """
        Encrypt data using ECIES-like hybrid encryption.
        Returns ephemeral public key and encrypted data
        """
        # Generate ephemeral key pair
        ephemeral_private = ec.generate_private_key(self._curve)
        ephemeral_public = ephemeral_private.public_key()

        # Perform key agreement
        shared_key = ephemeral_private.exchange(ec.ECDH(), public_key)

        # Derive encryption key
        encryption_key = self.derive_key(shared_key)

        # Return the ephemeral public key for later decryption
        serialized_public = ephemeral_public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        return serialized_public, encryption_key

    def decrypt(self, ephemeral_public_bytes, private_key):
        """
        Decrypt data using ECIES-like hybrid decryption.
        Returns the derived key
        """
        # Load the ephemeral public key
        ephemeral_public = serialization.load_pem_public_key(ephemeral_public_bytes)
        if not isinstance(ephemeral_public, ec.EllipticCurvePublicKey):
            raise ValueError("Invalid ephemeral public key format")

        # Perform key agreement
        shared_key = private_key.exchange(ec.ECDH(), ephemeral_public)

        # Derive decryption key
        decryption_key = self.derive_key(shared_key)

        return decryption_key
