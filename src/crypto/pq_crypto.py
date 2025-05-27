import oqs
from Crypto.Hash import SHA256, HMAC
from Crypto.Protocol.KDF import HKDF
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

class PQCrypto:
    def __init__(self):
        self.kem_alg = "Kyber512"
        self.sig_alg = "Dilithium2"
        self.aes_key_size = 24  # 192 bits

        self.kem = oqs.KeyEncapsulation(self.kem_alg)
        self.sig = oqs.Signature(self.sig_alg)

    def generate_keypair(self):
        """Generate a signature keypair"""
        public_key = self.sig.generate_keypair()
        private_key = self.sig.export_secret_key()
        return public_key, private_key

    def generate_dh_keypair(self):
        """Generate KEM keypair; returns public key only.
        Private key stays internal to self.kem."""
        public_key = self.kem.generate_keypair()
        return public_key  # private key is internal to self.kem

    def encapsulate_shared_secret(self, peer_public_key):
        """Encapsulate a shared secret using the peer's public key"""
        kem = oqs.KeyEncapsulation(self.kem_alg)
        ciphertext, shared_secret = kem.encap_secret(peer_public_key)
        return ciphertext, shared_secret

    def compute_shared_secret(self, ciphertext):
        """Decapsulate a shared secret using the server's KEM instance"""
        return self.kem.decap_secret(ciphertext)

    def derive_session_key(self, shared_secret, salt=None):
        """Use HKDF to derive an AES session key"""
        if salt is None:
            salt = b''

        key = HKDF(
            master=shared_secret,
            key_len=self.aes_key_size,
            salt=salt,
            hashmod=SHA256,
            num_keys=1
        )

        return key.ljust(self.aes_key_size, b'\0')[:self.aes_key_size]

    def encrypt_message(self, message, key):
        """Encrypt a message using AES-192-CBC"""
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(pad(message, AES.block_size))

    def decrypt_message(self, encrypted_data, key):
        """Decrypt a message using AES-192-CBC"""
        iv = encrypted_data[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(encrypted_data[AES.block_size:]), AES.block_size)

    def sign(self, message: bytes) -> bytes:
        """Sign using the already initialized sig context with generated key"""
        return self.sig.sign(message)

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify a signature using Dilithium2"""
        try:
            sig = oqs.Signature(self.sig_alg)
            sig.generate_keypair()
            sig.import_public_key(public_key)
            return sig.verify(message, signature)
        except Exception as e:
            print(f"Verification error: {e}")
            return False


    def create_hmac(self, message, key):
        """Create HMAC for message authentication"""
        return HMAC.new(key, message, SHA256).digest()

    def verify_hmac(self, message, hmac_value, key):
        """Verify HMAC for message authentication"""
        try:
            HMAC.new(key, message, SHA256).verify(hmac_value)
            return True
        except (ValueError, TypeError):
            return False
