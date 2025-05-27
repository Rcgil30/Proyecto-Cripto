import os
from dotenv import load_dotenv
from .classic_crypto import ClassicCrypto
from .pq_crypto import PQCrypto

# Load environment variables from .env file
load_dotenv()

class CryptoFactory:
    @staticmethod
    def create_crypto():
        """
        Create a crypto implementation based on environment variable.
        If USE_PQC=true, returns PQCrypto, otherwise returns ClassicCrypto.
        """
        use_pqc = os.getenv('USE_PQC', 'false').lower() == 'true'
        if use_pqc:
            return PQCrypto()
        return ClassicCrypto() 