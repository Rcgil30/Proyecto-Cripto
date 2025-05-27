# Proyecto-Cripto

## Post-Quantum Integration Points

### 1. **Key Exchange Algorithms** (Lines 50-70)

- Replace Diffie-Hellman/ECDH with post-quantum KEMs:
  - **CRYSTALS-Kyber** (NIST selected standard)
  - **NTRU**
  - **Classic McEliece**
- Implementation via `PostQuantumKeyExchange` abstract class

### 2. **Digital Signatures** (Lines 72-92)

- Replace RSA/ECDSA with post-quantum signatures:
  - **CRYSTALS-Dilithium** (NIST selected)
  - **FALCON** (NIST selected)
  - **SPHINCS+** (NIST selected)
- Implementation via `PostQuantumSignature` abstract class

### 3. **Symmetric Cryptography** (Lines 94-120)

- Strengthen against quantum attacks:
  - Use AES-256 instead of AES-128
  - Consider SHA-3 family hash functions
  - Increase MAC key sizes

### 4. **Hybrid Approaches** (Lines 110-112)

- Combine classical + post-quantum for transition period
- Examples: `ecdh-nistp256-kyber768`, `rsa-dilithium3`

## Key Metrics for Comparison

### **Performance Metrics**

- **Key Generation Time**: Time to generate keypairs (ms)
- **Signature/Verification Time**: Cryptographic operation latency
- **Encapsulation/Decapsulation Time**: KEM operation speed
- **Connection Establishment Time**: End-to-end handshake duration
- **Throughput**: Data transfer rate (MB/s)

### **Security Metrics**

- **Classical Security Level**: Bits of classical security
- **Quantum Security Level**: Bits of quantum resistance
- **Key Sizes**: Public/private key sizes in bytes
- **Signature Sizes**: Signature overhead in bytes
- **Ciphertext Sizes**: KEM ciphertext sizes

### **Network Metrics**

- **Handshake Overhead**: Additional bytes for PQ algorithms
- **Bandwidth Efficiency**: Useful data vs protocol overhead
- **Round Trip Count**: Number of network exchanges required
- **Protocol Compatibility**: Interoperability with existing SSH

### **Resource Metrics**

- **Memory Usage**: Peak and average RAM consumption
- **CPU Utilization**: Processing overhead percentage
- **Battery Impact**: Energy consumption on mobile devices
- **Cache Efficiency**: CPU cache hit rates

## Implementation Recommendations

### **For High Security**

- Use **Dilithium3** + **Kyber768** combination
- Implement certificate pinning for host keys
- Enable perfect forward secrecy

### **For Performance**

- Use **Falcon-512** for faster signatures
- Implement hybrid modes for gradual transition
- Optimize network round trips

### **For Compatibility**

- Implement algorithm negotiation with fallbacks
- Support both classical and post-quantum simultaneously
- Provide clear upgrade paths

### **For Constrained Environments**

- Use **Kyber512** for smaller key sizes
- Implement streaming/incremental operations
- Consider hardware acceleration where available

The implementation includes metric collection points throughout the code (marked as `METRICS COLLECTION POINT`) that would allow you to benchmark different post-quantum algorithms and compare their real-world performance in SSH deployments.

