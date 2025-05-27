from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF as PyCryptoHKDF
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import os

class PQCrypto:
    def __init__(self):
        # Initialize parameters
        self.key_size = 2048  # RSA key size
        self.aes_key_size = 24  # 192 bits for AES-192
    
    def generate_keypair(self):
        """Generate Ed25519 key pair for signatures"""
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ), private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
    
    def generate_dh_keypair(self):
        """Generate X25519 key pair for key exchange"""
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        return public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ), private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
    
    def compute_shared_secret(self, private_key, peer_public_key):
        """Compute shared secret using X25519"""
        private_key = x25519.X25519PrivateKey.from_private_bytes(private_key)
        public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_key)
        shared_secret = private_key.exchange(public_key)
        return shared_secret
    
    def derive_session_key(self, shared_secret, salt=None):
        """Derive a session key from the shared secret using HKDF"""
        # Use a fixed salt for testing
        if salt is None:
            salt = b'fixed_salt_for_testing_32bytes!!'
        
        # Use HKDF to derive a proper byte string key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=self.aes_key_size,
            salt=salt,
            info=b'session_key'
        )
        key = hkdf.derive(shared_secret)
        
        # Ensure we return exactly 24 bytes for AES-192
        if len(key) < self.aes_key_size:
            key = key + b'\0' * (self.aes_key_size - len(key))
        elif len(key) > self.aes_key_size:
            key = key[:self.aes_key_size]
        
        return key
    
    def encrypt_message(self, message, key):
        """Encrypt a message using AES-192-CBC"""
        # Generate a random IV
        iv = get_random_bytes(16)
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv)
        )
        encryptor = cipher.encryptor()
        
        # Pad the message
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(message) + padder.finalize()
        
        # Encrypt
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Return IV + ciphertext
        return iv + ciphertext
    
    def decrypt_message(self, encrypted_data, key):
        """Decrypt a message using AES-192-CBC"""
        try:
            # Extract IV and ciphertext
            iv = encrypted_data[:16]
            ciphertext = encrypted_data[16:]
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv)
            )
            decryptor = cipher.decryptor()
            
            # Decrypt
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Unpad
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            
            return plaintext
        except Exception as e:
            print(f"Decryption error: {e}")
            raise
    
    def sign(self, message, private_key):
        """Sign a message using Ed25519"""
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key)
        signature = private_key.sign(message)
        return signature
    
    def verify(self, message, signature, public_key):
        """Verify a signature using Ed25519"""
        try:
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
            public_key.verify(signature, message)
            return True
        except Exception as e:
            print(f"Verification error: {e}")
            return False
    
    def create_hmac(self, message, key):
        """Create HMAC for message authentication"""
        h = hashes.Hash(hashes.SHA256())
        h.update(key)
        h.update(message)
        return h.finalize()
    
    def verify_hmac(self, message, hmac, key):
        """Verify HMAC for message authentication"""
        try:
            h = hashes.Hash(hashes.SHA256())
            h.update(key)
            h.update(message)
            computed_hmac = h.finalize()
            return hmac == computed_hmac
        except Exception:
            return False 