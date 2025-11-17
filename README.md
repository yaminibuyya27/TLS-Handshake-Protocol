# TLS Handshake Protocol

A complete implementation of the TLS handshake protocol from scratch demonstrating RSA authentication, Diffie-Hellman key exchange, key derivation, and encrypted communication.

## Project Overview

This project implements a TLS (Transport Layer Security) handshake protocol that demonstrates how HTTPS and secure web communication work. The implementation:

1. Authenticates server identity using RSA digital signatures
2. Establishes a shared secret using Diffie-Hellman key exchange
3. Derives strong session keys using a Key Derivation Function (KDF)
4. Provides encrypted bidirectional communication
5. Ensures Perfect Forward Secrecy and replay protection

## Project Structure
```
SimpleTLS/
├── src/
│   ├── crypto/
│   │   ├── MathUtils.java          # Modular arithmetic & prime generation
│   │   ├── RSA.java                # RSA implementation
│   │   ├── DiffieHellman.java      # Diffie-Hellman key exchange
│   │   └── KDF.java                # Key Derivation Function
│   │
│   ├── protocol/
│   │   ├── TLSMessage.java         # Message format & serialization
│   │   ├── HandshakeState.java     # State machine
│   │   ├── TLSServer.java          # Server-side handshake logic
│   │   └── TLSClient.java          # Client-side handshake logic
│   │
│   ├── utils/
│   │   ├── ByteUtils.java          # Byte operations
│   │   └── Colors.java             # Terminal output colors
│   │
│   └── Main.java                   # Demo application
│
└── README.md                       # This file
```

## Prerequisites

* **Java Development Kit (JDK):** Version 8 or higher

## Running the Application

Demonstrates the complete 6-phase TLS handshake protocol.
```bash
# Check Java version
java -version

# Compile all files
javac -d bin src/**/*.java src/*.java

# Run server and Client in seperate terminals
#  Terminal 1 (Server):
java -cp bin Main server

#  Terminal 2 (Client):
java -cp bin Main client
```

**Features:**
* Generates RSA key pairs for server authentication
* Implements Diffie-Hellman key exchange
* Derives session keys using KDF with 10,000 iterations
* Demonstrates encrypted bidirectional communication
* Shows Perfect Forward Secrecy through ephemeral keys
* Includes replay protection with random nonces

**What Happens:**
* **Phase 1:** Server initialization (RSA key generation ~3 seconds)
* **Phase 2:** Client Hello (client sends random nonce)
* **Phase 3:** Server Hello + Certificate (server sends RSA public key and DH parameters)
* **Phase 4:** Client Key Exchange (both parties compute shared secret)
* **Phase 5:** Handshake Finalization (verify matching session keys)
* **Phase 6:** Encrypted Communication (secure message exchange)

**Total Runtime:** 3-4 seconds

## Component Details

### Mathematical Primitives (MathUtils.java)

Implements core mathematical operations for cryptography.
```bash
# Used internally by RSA and DH
```

**Features:**
* `modPow()` - Modular exponentiation using repeated squaring
* `isProbablePrime()` - Miller-Rabin primality test (10 iterations)
* `generatePrime()` - Generate random prime numbers
* `modInverse()` - Extended Euclidean Algorithm for modular inverse

### RSA Authentication (RSA.java)

Implements RSA for server authentication.
```bash
# Used internally by server
```

**Features:**
* Generates RSA key pairs (2048-bit)
* Public key (e, n) - shared with client
* Private key (d, n) - kept secret by server
* SHA-256 message hashing

### Diffie-Hellman Key Exchange (DH.java)

Implements secure key exchange with Perfect Forward Secrecy.
```bash
# Used by both client and server
```

**Features:**
* Generates public parameters (p, g)
* Computes public keys (g^a mod p, g^b mod p)
* Derives shared secret (g^ab mod p)
* Ephemeral keys generated per session
* Both parties compute same shared secret without transmitting it

### Key Derivation Function (KDF.java)

Derives strong encryption keys from the Diffie-Hellman shared secret.
```bash
# Used after DH key exchange
```

**Features:**
* Takes shared secret as input
* Performs iterative hashing (default: 10,000 iterations)
* Outputs two separate keys:
    - Encryption key (16 bytes)
    - MAC key (16 bytes)
* Uses SHA-256 hash function

### TLS Protocol (protocol/ directory)

Implements the complete TLS handshake protocol.
```bash
# Orchestrated by Main.java
```

**Features:**
* Message serialization (Type-Length-Value format)
* State machine with 9 states for protocol flow control
* Server and client handshake logic
* Encrypted FINISHED messages for key verification
* XOR encryption

**Expected Results:**
* Program completes in 3-4 seconds
* All 6 phases execute successfully
* Both client and server compute same shared secret
* Encrypted communication succeeds
* No compilation or runtime errors

## Troubleshooting

**"Could not find or load main class"**
```bash
# Make sure you're in the src directory
cd src
java Main

# If .class files are in different directory:
java -cp . Main
```

**"Class not found" errors**
```bash
# Recompile all dependencies
javac crypto/MathUtils.java crypto/SimpleRSA.java crypto/SimpleDH.java crypto/SimpleKDF.java utils/ByteUtils.java utils/Colors.java protocol/TLSMessage.java protocol/HandshakeState.java protocol/TLSServer.java protocol/TLSClient.java Main.java
```

**Prime generation takes too long**
```bash
# This is expected for 2048-bit keys (~3 seconds)
# Normal behavior - no action needed
```

## Implementation Notes

**From Scratch (No External Crypto Libraries):**

* Modular exponentiation (repeated squaring algorithm)
* Miller-Rabin primality testing
* RSA key generation, encryption, decryption
* Diffie-Hellman key exchange
* Key derivation function (10,000 iterations)
* Complete TLS handshake protocol

**Using Java Standard Library:**

* `BigInteger` - For large number storage only
* `SecureRandom` - For random byte generation
* `MessageDigest` - For SHA-256 hashing

## Security Properties

**Achieved:**

* Confidentiality - All data encrypted with session keys
* Authentication - Server proves identity via RSA
* Perfect Forward Secrecy - Ephemeral DH keys per session
* Replay Protection - Random nonces and session IDs
* Key Derivation - Strong session keys from shared secret
