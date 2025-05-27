import time
import statistics
from dataclasses import dataclass
from typing import Dict, List
import json
import os
from datetime import datetime

@dataclass
class CryptoMetrics:
    key_generation_time: float
    key_exchange_time: float
    encryption_time: float
    decryption_time: float
    signature_time: float
    verification_time: float
    public_key_size: int
    private_key_size: int
    ciphertext_size: int
    signature_size: int
    message_size: int

class MetricsCollector:
    def __init__(self):
        self.metrics: List[CryptoMetrics] = []
        self.start_time = None
        self.crypto_type = None

    def start_operation(self, crypto_type: str):
        """Start timing an operation"""
        self.crypto_type = crypto_type
        self.start_time = time.time()

    def end_operation(self) -> float:
        """End timing an operation and return elapsed time"""
        if self.start_time is None:
            return 0.0
        elapsed = time.time() - self.start_time
        self.start_time = None
        return elapsed

    def record_metrics(self, metrics: CryptoMetrics):
        """Record metrics"""
        self.metrics.append(metrics)

    def get_average_metrics(self) -> CryptoMetrics:
        """Calculate average metrics"""
        if not self.metrics:
            return None

        return CryptoMetrics(
            key_generation_time=statistics.mean(m.key_generation_time for m in self.metrics),
            key_exchange_time=statistics.mean(m.key_exchange_time for m in self.metrics),
            encryption_time=statistics.mean(m.encryption_time for m in self.metrics),
            decryption_time=statistics.mean(m.decryption_time for m in self.metrics),
            signature_time=statistics.mean(m.signature_time for m in self.metrics),
            verification_time=statistics.mean(m.verification_time for m in self.metrics),
            public_key_size=statistics.mean(m.public_key_size for m in self.metrics),
            private_key_size=statistics.mean(m.private_key_size for m in self.metrics),
            ciphertext_size=statistics.mean(m.ciphertext_size for m in self.metrics),
            signature_size=statistics.mean(m.signature_size for m in self.metrics),
            message_size=statistics.mean(m.message_size for m in self.metrics)
        )

    def save_metrics(self, filename: str = None):
        """Save metrics to a JSON file"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"crypto_metrics_{timestamp}.json"

        metrics_dict = {
            'metrics': [vars(m) for m in self.metrics],
            'average': vars(self.get_average_metrics())
        }

        with open(filename, 'w') as f:
            json.dump(metrics_dict, f, indent=2)

    def print_metrics(self):
        """Print metrics for the current crypto type"""
        avg = self.get_average_metrics()
        if not avg:
            print("No metrics available")
            return

        crypto_type = 'Post-Quantum' if os.getenv('USE_PQC', 'false').lower() == 'true' else 'Classical'
        print(f"\n{crypto_type} Cryptographic Performance Metrics")
        print("=" * 50)
        print(f"{'Operation':<20} {'Time (ms)':<15} {'Size (bytes)':<15}")
        print("-" * 50)
        
        operations = [
            ('Key Generation', avg.key_generation_time * 1000, avg.public_key_size),
            ('Key Exchange', avg.key_exchange_time * 1000, None),
            ('Encryption', avg.encryption_time * 1000, avg.ciphertext_size),
            ('Decryption', avg.decryption_time * 1000, None),
            ('Signature', avg.signature_time * 1000, avg.signature_size),
            ('Verification', avg.verification_time * 1000, None)
        ]

        for name, time_ms, size in operations:
            if size is not None:
                print(f"{name:<20} {time_ms:>10.2f} ms {size:>10} B")
            else:
                print(f"{name:<20} {time_ms:>10.2f} ms {'N/A':>10}") 