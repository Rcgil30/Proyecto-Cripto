from .classic_crypto import ClassicCrypto
from .pq_crypto import PQCrypto

class CryptoFactory:
    @staticmethod
    def create_crypto(use_pqc=False):
        """
        Create a crypto instance based on the specified type.
        
        Args:
            use_pqc (bool): If True, returns a post-quantum crypto instance.
                           If False, returns a classical crypto instance.
        
        Returns:
            ClassicCrypto or PQCrypto: The appropriate crypto instance.
        """
        if use_pqc:
            return PQCrypto()
        return ClassicCrypto() 