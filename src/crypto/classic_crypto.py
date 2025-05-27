from Crypto.PublicKey import RSA, ECC
from Crypto.Hash import SHA256, HMAC
from Crypto.Protocol.KDF import HKDF
from Crypto.Cipher import AES
from Crypto.Signature import pkcs1_15, DSS
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import os

class ClassicCrypto:
    def __init__(self):
        # Initialize parameters
        self.key_size = 2048  # RSA key size
        self.aes_key_size = 24  # 192 bits for AES-192
        
        # Generate DH parameters
        self.dh_parameters = ECC.generate(curve='P-256')
    
    def generate_keypair(self):
        """Generate RSA key pair for signatures"""
        key = RSA.generate(self.key_size)
        return key.publickey(), key
    
    def generate_dh_keypair(self):
        """Generate ECC key pair for key exchange"""
        private_key = ECC.generate(curve='P-256')
        public_key = private_key.public_key()
        return public_key, private_key
    
    def compute_shared_secret(self, private_key, peer_public_key):
        """Compute shared secret using ECC"""
        return private_key.d * peer_public_key.pointQ
    
    def derive_session_key(self, shared_secret, salt=None):
        """Derive a session key from the shared secret using HKDF"""
        # Use a fixed salt for testing
        if salt is None:
            salt = b'fixed_salt_for_testing_32bytes!!'
        
        # Convert shared secret point to bytes by concatenating x and y coordinates
        shared_secret_bytes = f"{shared_secret.x}:{shared_secret.y}".encode()
        
        # Use HKDF to derive a proper byte string key
        key = HKDF(
            master=shared_secret_bytes,
            key_len=self.aes_key_size,  # 24 bytes for AES-192
            salt=salt,
            hashmod=SHA256,
            num_keys=1
        )[0]
        
        # Ensure we return exactly 24 bytes for AES-192
        if isinstance(key, int):
            key = key.to_bytes((key.bit_length() + 7) // 8, 'big')
        
        # Pad or truncate to exactly 24 bytes
        if len(key) < self.aes_key_size:
            key = key + b'\0' * (self.aes_key_size - len(key))
        elif len(key) > self.aes_key_size:
            key = key[:self.aes_key_size]
        
        return key
    
    def encrypt_message(self, message, key):
        """Encrypt a message using AES-192-CBC"""
        # Generate a random IV
        iv = get_random_bytes(AES.block_size)
        
        # Create cipher
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Pad the message to AES block size
        padded_message = pad(message, AES.block_size)
        
        # Encrypt the padded message
        ciphertext = cipher.encrypt(padded_message)
        
        # Return IV + ciphertext
        return iv + ciphertext
    
    def decrypt_message(self, encrypted_data, key):
        """Decrypt a message using AES-192-CBC"""
        try:
            # Extract IV and ciphertext
            iv = encrypted_data[:AES.block_size]
            ciphertext = encrypted_data[AES.block_size:]
            
            # Create cipher
            cipher = AES.new(key, AES.MODE_CBC, iv)
            
            # Decrypt and unpad
            padded_plaintext = cipher.decrypt(ciphertext)
            plaintext = unpad(padded_plaintext, AES.block_size)
            return plaintext
        except ValueError as e:
            print(f"Decryption error: {e}")
            raise
    
    def sign(self, message, private_key):
        """Sign a message using RSA or ECC"""
        hash_obj = SHA256.new(message)
        
        if isinstance(private_key, RSA.RsaKey):
            signature = pkcs1_15.new(private_key).sign(hash_obj)
            return signature
        elif isinstance(private_key, ECC.EccKey):
            signer = DSS.new(private_key, 'fips-186-3')
            signature = signer.sign(hash_obj)
            return signature
        else:
            raise ValueError("Unsupported key type for signing")
    
    def verify(self, message, signature, public_key):
        """Verify a signature using RSA or ECC"""
        try:
            hash_obj = SHA256.new(message)
            
            if isinstance(public_key, RSA.RsaKey):
                # Ensure signature is in the correct format
                if isinstance(signature, str):
                    signature = bytes.fromhex(signature)
                pkcs1_15.new(public_key).verify(hash_obj, signature)
            elif isinstance(public_key, ECC.EccKey):
                # Ensure signature is in the correct format
                if isinstance(signature, str):
                    signature = bytes.fromhex(signature)
                verifier = DSS.new(public_key, 'fips-186-3')
                verifier.verify(hash_obj, signature)
            else:
                raise ValueError("Unsupported key type for verification")
            return True
        except (ValueError, TypeError) as e:
            print(f"Verification error: {e}")
            return False
    
    def create_hmac(self, message, key):
        """Create HMAC for message authentication"""
        hmac = HMAC.new(key, message, SHA256)
        return hmac.digest()
    
    def verify_hmac(self, message, hmac, key):
        """Verify HMAC for message authentication"""
        try:
            hmac_obj = HMAC.new(key, message, SHA256)
            hmac_obj.verify(hmac)
            return True
        except (ValueError, TypeError):
            return False 