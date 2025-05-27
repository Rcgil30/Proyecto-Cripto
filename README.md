# SSH Client-Server Implementation

A secure SSH client-server implementation supporting both classical and post-quantum cryptography.

## Features

- Support for both classical and post-quantum cryptography
- Classical cryptography:
  - Key Exchange: ECDH-P256
  - Signature: RSA-SHA256
  - Encryption: AES-192-CBC
  - MAC: HMAC-SHA256
- Post-quantum cryptography:
  - Key Exchange: Kyber512
  - Signature: Dilithium2
  - Encryption: AES-192-CBC
  - MAC: HMAC-SHA256

## Prerequisites

- Python 3.9 or higher
- pip (Python package manager)
- Build tools (for installing liboqs-python):
  - On Ubuntu/Debian: `sudo apt-get install build-essential python3-dev`
  - On Windows: Visual Studio Build Tools
  - On macOS: Xcode Command Line Tools

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd <repository-name>
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

Note: If you encounter issues installing `liboqs-python`, you may need to install additional build dependencies first. See the Prerequisites section above.

## Configuration

Create a `.env` file in the root directory with the following variables:

```env
# Server Configuration
HOST=localhost
PORT=2222
MAX_CONNECTIONS=1
USE_PQC=false  # Set to true to use post-quantum cryptography

# Client Configuration
HOST=localhost
PORT=2222
USE_PQC=false  # Set to true to use post-quantum cryptography
```

## Usage

### Starting the Server

1. Open a terminal and navigate to the project directory
2. Run the server:
```bash
python -m src.server.ssh_server
```

The server will start and listen for connections on the configured host and port.

### Using the Client

1. Open another terminal and navigate to the project directory
2. Run the client:
```bash
python -m src.client.ssh_client
```

3. Once connected, you can:
   - Type messages and press Enter to send them
   - Type 'quit' to exit the client

## Important Notes

1. The server only accepts one connection at a time
2. Both client and server must use the same cryptography mode (classical or post-quantum)
3. The signature verification is currently disabled and will be implemented in a future update
4. Make sure the `.env` file is properly configured before running either the client or server

## Security Considerations

- This is a demonstration implementation and should not be used in production without proper security review
- The post-quantum cryptography implementation uses experimental algorithms
- Always use strong, unique keys in production environments
- Keep your dependencies up to date

