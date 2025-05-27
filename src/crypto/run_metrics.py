import asyncio
import os
from dotenv import load_dotenv
from .crypto_factory import CryptoFactory
from .crypto_metrics import MetricsCollector, CryptoMetrics
from datetime import datetime

# Load environment variables
load_dotenv()

async def run_performance_test(metrics_collector: MetricsCollector, num_iterations: int = 10):
    """Run a performance test for the configured crypto type"""
    crypto = CryptoFactory.create_crypto()
    crypto_type = 'post_quantum' if os.getenv('USE_PQC', 'false').lower() == 'true' else 'classical'
    test_message = b"Hello, this is a test message for cryptographic performance testing!"

    for _ in range(num_iterations):
        # Key Generation
        metrics_collector.start_operation(crypto_type)
        public_key, private_key = crypto.generate_keypair()
        key_gen_time = metrics_collector.end_operation()

        # Key Exchange
        metrics_collector.start_operation(crypto_type)
        if crypto_type == 'post_quantum':
            peer_public_key = crypto.generate_dh_keypair()
            ciphertext, shared_secret = crypto.encapsulate_shared_secret(peer_public_key)
            shared_secret = crypto.compute_shared_secret(ciphertext)
        else:
            peer_public_key, _ = crypto.generate_dh_keypair()
            shared_secret = crypto.compute_shared_secret(private_key, peer_public_key)
        key_exchange_time = metrics_collector.end_operation()

        # Encryption
        metrics_collector.start_operation(crypto_type)
        session_key = crypto.derive_session_key(shared_secret)
        encrypted_message = crypto.encrypt_message(test_message, session_key)
        encryption_time = metrics_collector.end_operation()

        # Decryption
        metrics_collector.start_operation(crypto_type)
        decrypted_message = crypto.decrypt_message(encrypted_message, session_key)
        decryption_time = metrics_collector.end_operation()

        # Signature
        metrics_collector.start_operation(crypto_type)
        if crypto_type == 'post_quantum':
            signature = crypto.sign(test_message)
        else:
            signature = crypto.sign(test_message, private_key)
        signature_time = metrics_collector.end_operation()

        # Verification
        metrics_collector.start_operation(crypto_type)
        verification_result = crypto.verify(test_message, signature, public_key)
        verification_time = metrics_collector.end_operation()

        # Record metrics
        metrics = CryptoMetrics(
            key_generation_time=key_gen_time,
            key_exchange_time=key_exchange_time,
            encryption_time=encryption_time,
            decryption_time=decryption_time,
            signature_time=signature_time,
            verification_time=verification_time,
            public_key_size=len(public_key.export_key()) if hasattr(public_key, 'export_key') else len(public_key),
            private_key_size=len(private_key.export_key()) if hasattr(private_key, 'export_key') else len(private_key),
            ciphertext_size=len(encrypted_message),
            signature_size=len(signature),
            message_size=len(test_message)
        )
        metrics_collector.record_metrics(metrics)

async def main():
    # Create metrics directory if it doesn't exist
    os.makedirs('metrics', exist_ok=True)

    # Initialize metrics collector
    metrics_collector = MetricsCollector()

    # Run tests for the configured crypto type
    crypto_type = 'Post-Quantum' if os.getenv('USE_PQC', 'false').lower() == 'true' else 'Classical'
    print(f"Running {crypto_type} cryptography tests...")
    await run_performance_test(metrics_collector)

    # Print metrics
    metrics_collector.print_metrics()

    # Save metrics to file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    metrics_collector.save_metrics(f'metrics/crypto_metrics_{crypto_type.lower()}_{timestamp}.json')

if __name__ == "__main__":
    asyncio.run(main()) 