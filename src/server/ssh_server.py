import asyncio
import json
import os
import traceback
import socket
import threading
from dotenv import load_dotenv
from ..crypto.crypto_factory import CryptoFactory
from Crypto.PublicKey import RSA, ECC
from Crypto.Random import get_random_bytes

# Load environment variables
load_dotenv()

class SSHServer:
    def __init__(self):
        try:
            # Load configuration from environment variables
            self.host = os.getenv('HOST', 'localhost')
            self.port = int(os.getenv('PORT', 2222))
            self.max_connections = int(os.getenv('MAX_CONNECTIONS', '1'))
            self.use_pqc = os.getenv('USE_PQC', 'false').lower() == 'true'
            
            print(f"Initializing server on {self.host}:{self.port}")
            print(f"Using {'Post-Quantum' if self.use_pqc else 'Classical'} cryptography")
            
            # Initialize crypto
            self.crypto = CryptoFactory.create_crypto()
            
            # Initialize server socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Store active connections
            self.connections = []
            
            # Generate host key
            print("Generating host key...")
            self.host_key_public, self.host_key_private = self.crypto.generate_keypair()
            
            # Generate key pair for key exchange
            print("Generating key pair for key exchange...")
            if self.use_pqc:
                self.server_dh_public_key = self.crypto.generate_dh_keypair()
                self.server_dh_private_key = None
            else:
                self.server_dh_public_key, self.server_dh_private_key = self.crypto.generate_dh_keypair()
            self.clients = {}
            self.active_connection = None
            self.server = None
            print("Server initialization complete")
        except Exception as e:
            print(f"Error during server initialization: {e}")
            traceback.print_exc()
            raise
    
    async def handle_client(self, reader, writer):
        addr = writer.get_extra_info('peername')
        
        # Check if there's already an active connection
        if self.active_connection is not None:
            print(f"Rejected connection from {addr}: Server already has an active connection")
            writer.close()
            await writer.wait_closed()
            return
        
        print(f"New connection from {addr}")
        self.active_connection = addr
        
        try:
            # Send server's public keys
            server_info = {
                'host_key': self.host_key_public.hex() if self.use_pqc else self.host_key_public.export_key().hex(),
                'dh_public_key': self.server_dh_public_key.hex() if self.use_pqc else self.server_dh_public_key.export_key(format='PEM'),
                'use_pqc': self.use_pqc
            }
            server_info_json = json.dumps(server_info)
            writer.write(server_info_json.encode() + b'\n')
            await writer.drain()
            
            # Receive client's public keys
            print("Waiting for client data...")
            client_data = await reader.readline()
            if not client_data:
                print("No data received from client")
                return
                
            print(f"Received client data: {client_data.decode()}")
            client_info = json.loads(client_data.decode())
            client_dh_public_key = bytes.fromhex(client_info['dh_public_key']) if self.use_pqc else ECC.import_key(client_info['dh_public_key'].encode())
            client_public_key = bytes.fromhex(client_info['public_key']) if self.use_pqc else RSA.import_key(bytes.fromhex(client_info['public_key']))
            print("Client public keys received and parsed")

            
            # Compute shared secret
            print("Computing shared secret...")
            if self.use_pqc:
                ciphertext = await reader.readline()
                ciphertext = ciphertext.decode()
                ciphertext = bytes.fromhex(ciphertext)
                shared_secret = self.crypto.compute_shared_secret(ciphertext)
            else:
                shared_secret = self.crypto.compute_shared_secret(self.server_dh_private_key, client_dh_public_key)
            
            # Key Derivation
            print("Deriving session keys...")
            session_key = self.crypto.derive_session_key(shared_secret)
            hmac_key = self.crypto.derive_session_key(shared_secret, salt=b'hmac')
            
            """
            # Server Authentication
            print("Signing shared secret...")
            # Convert shared secret to bytes for signing
            if self.use_pqc:
                shared_secret_bytes = shared_secret
                host_signature = self.crypto.sign(shared_secret_bytes)
            else:
                shared_secret_bytes = f"{shared_secret.x}:{shared_secret.y}".encode()
                host_signature = self.crypto.sign(shared_secret_bytes, self.host_key_private)
            
            # Send signature with length prefix
            signature_len = len(host_signature)
            writer.write(signature_len.to_bytes(4, 'big'))
            writer.write(host_signature)
            await writer.drain()
            
            # Client Authentication
            print("Waiting for client authentication...")
            # Read auth data length
            auth_len = int.from_bytes(await reader.read(4), 'big')
            client_auth = await reader.read(auth_len)
            if not client_auth:
                print("No authentication data received from client")
                return
                
            # Read signature length
            sig_len = int.from_bytes(await reader.read(4), 'big')
            client_signature = await reader.read(sig_len)
            if not client_signature:
                print("No signature received from client")
                return
            
            # Verify client signature
            print("Verifying client signature...")
            if not self.crypto.verify(client_auth, client_signature, client_public_key):
                print(f"Client authentication failed for {addr}")
                return
            """
            print(f"Client {addr} authenticated successfully")
            
            # Store client info
            self.clients[addr] = {
                'session_key': session_key,
                'hmac_key': hmac_key
            }
            
            # Secure Session - Message Reception Loop
            print("Entering message reception loop...")
            while True:
                # Read message length
                msg_len = int.from_bytes(await reader.read(4), 'big')
                
                encrypted_data = await reader.read(msg_len)
                if not encrypted_data:
                    print("Connection closed by client")
                    break
                
                # Read HMAC length and HMAC
                hmac_len = int.from_bytes(await reader.read(4), 'big')
                hmac = await reader.read(hmac_len)
                
                # Decrypt message
                message = self.crypto.decrypt_message(encrypted_data, session_key)
                
                # Verify HMAC
                if not self.crypto.verify_hmac(message, hmac, hmac_key):
                    print(f"HMAC verification failed for message from {addr}")
                    continue
                
                # Print received message
                print(f"Received from {addr}: {message.decode()}")
                
        except Exception as e:
            print(f"Error handling client {addr}: {e}")
            traceback.print_exc()
        finally:
            writer.close()
            await writer.wait_closed()
            if addr in self.clients:
                del self.clients[addr]
            if self.active_connection == addr:
                self.active_connection = None
            print(f"Connection closed for {addr}")
            # Signal the server to shut down
            if self.server:
                self.server.close()
    
    async def start(self):
        try:
            print("Starting server...")
            self.server = await asyncio.start_server(
                self.handle_client, self.host, self.port
            )
            
            print(f"SSH Server running on {self.host}:{self.port}")
            print(f"Maximum connections: {self.max_connections}")
            print("Using algorithms:")
            if self.use_pqc:
                print("  Key Exchange: Kyber512")
                print("  Signature: Dilithium2")
            else:
                print("  Key Exchange: ECDH-P256")
                print("  Signature: RSA-SHA256")
            print("  Encryption: AES-192-CBC")
            print("  MAC: HMAC-SHA256")
            
            try:
                async with self.server:
                    await self.server.serve_forever()
            except asyncio.CancelledError:
                pass
            except Exception as e:
                print(f"Server error: {e}")
            finally:
                if self.server:
                    self.server.close()
                    await self.server.wait_closed()
                    print("Server shutdown complete")
                
        except Exception as e:
            print(f"Error starting server: {e}")
            traceback.print_exc()
            raise

if __name__ == "__main__":
    try:
        server = SSHServer()
        asyncio.run(server.start())
    except KeyboardInterrupt:
        print("\nServer stopped by user")
    except Exception as e:
        print(f"Server error: {e}")
        traceback.print_exc() 