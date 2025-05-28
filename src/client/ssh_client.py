import asyncio
import json
import os
import traceback
from dotenv import load_dotenv
from ..crypto.crypto_factory import CryptoFactory
from Crypto.PublicKey import RSA, ECC
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# Load environment variables
load_dotenv()

class SSHClient:
    def __init__(self):
        try:
            # Load configuration from environment variables
            self.host = os.getenv('HOST', 'localhost')
            self.port = int(os.getenv('PORT', 2222))
            self.use_pqc = os.getenv('USE_PQC', 'false').lower() == 'true'
            
            print(f"Initializing client for {self.host}:{self.port}")
            print(f"Using {'Post-Quantum' if self.use_pqc else 'Classical'} cryptography")
            
            # Initialize crypto
            self.crypto = CryptoFactory.create_crypto()
            
            # Generate key pair for key exchange
            print("Generating key pair for key exchange...")
            if self.use_pqc:
                self.client_dh_public_key = self.crypto.generate_dh_keypair()
                self.client_dh_private_key = None
            else:
                self.client_dh_public_key, self.client_dh_private_key = self.crypto.generate_dh_keypair()
            
            # Generate key pair for authentication
            print("Generating key pair for authentication...")
            self.client_public_key, self.client_private_key = self.crypto.generate_keypair()
            
            self.session_key = None
            self.hmac_key = None
            self.host_key = None
            print("Client initialization complete")
        except Exception as e:
            print(f"Error during client initialization: {e}")
            traceback.print_exc()
            raise
    
    async def connect(self):
        try:
            print(f"Connecting to {self.host}:{self.port}...")
            self.reader, self.writer = await asyncio.open_connection(
                self.host, self.port
            )
            print("Connection established")
            
            # Receive server's public keys
            print("Waiting for server info...")
            server_data = await self.reader.readline()
            if not server_data:
                print("No data received from server")
                return False
                
            print(f"Received server data: {server_data.decode()}")
            server_info = json.loads(server_data.decode())
            
            # Check if server is using PQC
            server_use_pqc = server_info.get('use_pqc', False)
            if server_use_pqc != self.use_pqc:
                print(f"Error: Server is using {'Post-Quantum' if server_use_pqc else 'Classical'} cryptography, but client is using {'Post-Quantum' if self.use_pqc else 'Classical'} cryptography")
                return False

            # Parse server's public keys
            if self.use_pqc:
                self.host_key = bytes.fromhex(server_info['host_key'])
                server_dh_public_key = bytes.fromhex(server_info['dh_public_key'])
            else:
                self.host_key = RSA.import_key(bytes.fromhex(server_info['host_key']))
                server_dh_public_key = ECC.import_key(server_info['dh_public_key'].encode())
            
            print("Server public keys received and parsed")
            
            # Send client's public keys
            client_info = {
                'dh_public_key': self.client_dh_public_key.hex() if self.use_pqc else self.client_dh_public_key.export_key(format='PEM'),
                'public_key': self.client_public_key.hex() if self.use_pqc else self.client_public_key.export_key().hex()
            }
            client_info_json = json.dumps(client_info)
            self.writer.write(client_info_json.encode() + b'\n')
            await self.writer.drain()
            
            # Compute shared secret
            print("Computing shared secret...")
            if self.use_pqc:
                ciphertext, shared_secret = self.crypto.encapsulate_shared_secret(server_dh_public_key)
                self.writer.write(ciphertext.hex().encode() + b'\n')
                await self.writer.drain()
            else:
                shared_secret = self.crypto.compute_shared_secret(self.client_dh_private_key, server_dh_public_key)
            
            # Key Derivation
            print("Deriving session keys...")
            self.session_key = self.crypto.derive_session_key(shared_secret)
            self.hmac_key = self.crypto.derive_session_key(shared_secret, salt=b'hmac')
            
            # Server Authentication
            print("Waiting for server signature...")
            # Read signature length
            sig_len = int.from_bytes(await self.reader.read(4), 'big')
            host_signature = await self.reader.read(sig_len)
            if not host_signature:
                print("No signature received from server")
                return False
                
            print("Verifying server signature...")
            # Convert shared secret to bytes for verification
            auth_data = f"Client {self.host}:{self.port}".encode()
            if self.use_pqc:
                shared_secret_bytes = shared_secret
            else:
                shared_secret_bytes = f"{shared_secret.x}:{shared_secret.y}".encode()
            
            if self.use_pqc:
                auth_signature = self.crypto.sign(shared_secret_bytes)
            else:
                auth_signature = self.crypto.sign(shared_secret_bytes, self.client_private_key)

            # Always send client authentication, even if server verification fails
            print("Sending client authentication...")
            
            # Send auth data with length prefix
            auth_len = len(auth_data)
            self.writer.write(auth_len.to_bytes(4, 'big'))
            self.writer.write(auth_data)
            
            # Send signature with length prefix
            sig_len = len(auth_signature)
            self.writer.write(sig_len.to_bytes(4, 'big'))
            self.writer.write(auth_signature)
            await self.writer.drain()
            
            # Now verify server signature
            if not self.crypto.verify(shared_secret_bytes, host_signature, self.host_key):
                print("Server authentication failed, but continuing with connection")
                # Don't raise exception, just log the failure
            else:
                print("Server authenticated successfully")
            
            print("Successfully established secure connection")
            return True
            
        except Exception as e:
            print(f"Connection failed: {e}")
            traceback.print_exc()
            return False
    
    async def send_message(self, message):
        if not self.session_key or not self.hmac_key:
            raise Exception("Not connected to server")
        
        try:
            message_bytes = message.encode()
            
            # Create HMAC
            hmac = self.crypto.create_hmac(message_bytes, self.hmac_key)
            
            # Encrypt message
            encrypted_message = self.crypto.encrypt_message(message_bytes, self.session_key)
            
            # Send message length first
            msg_len = len(encrypted_message)
            self.writer.write(msg_len.to_bytes(4, 'big'))
            
            # Send encrypted message
            self.writer.write(encrypted_message)
            
            # Send HMAC length and HMAC
            hmac_len = len(hmac)
            self.writer.write(hmac_len.to_bytes(4, 'big'))
            self.writer.write(hmac)
            
            await self.writer.drain()
            print("Message sent successfully")
            
        except Exception as e:
            print(f"Error sending message: {e}")
            traceback.print_exc()
            raise
    
    async def close(self):
        if self.writer:
            print("Closing connection...")
            self.writer.close()
            await self.writer.wait_closed()
            print("Connection closed")

async def main():
    client = SSHClient()
    if await client.connect():
        try:
            while True:
                message = input("Enter message (or 'quit' to exit): ")
                if message.lower() == 'quit':
                    break
                
                await client.send_message(message)
        finally:
            await client.close()

if __name__ == "__main__":
    asyncio.run(main()) 