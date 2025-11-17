package crypto;

import utils.MathUtils;

import java.math.BigInteger;

public class DiffieHellman {

    private final BigInteger p;  // Large prime
    private final BigInteger g;  // Generator
    private BigInteger privateKey;
    private BigInteger publicKey;


     // Initialize with public parameters p and g
    public DiffieHellman(BigInteger p, BigInteger g) {
        this.p = p;
        this.g = g;
    }


     // Generate public DH parameters (p and g) p is a prime, g is a generator
    public static DHParameters generateParameters(int bitLength) {
        System.out.println("Generating DH parameters (" + bitLength + "-bit prime)...");

        // Generating a prime p
        BigInteger p = MathUtils.generatePrime(bitLength);

        // Using g = 2 (common generator choice)
        BigInteger g = BigInteger.valueOf(2);

        System.out.println("DH parameters generated!");

        return new DHParameters(p, g);
    }


     // Generate private key (random number < p)
    public void generatePrivateKey() {
        // Private key is random value in range [2, p-2]
        this.privateKey = MathUtils.randomBigInteger(
                BigInteger.valueOf(2),
                p.subtract(BigInteger.valueOf(2))
        );
    }


     // Compute public key: g^privateKey mod p
    public BigInteger computePublicKey() {
        if (privateKey == null) {
            throw new IllegalStateException("Generate private key first!");
        }

        this.publicKey = MathUtils.modPow(g, privateKey, p);
        return this.publicKey;
    }


     // Compute shared secret: otherPublicKey^privateKey mod p
    public BigInteger computeSharedSecret(BigInteger otherPublicKey) {
        if (privateKey == null) {
            throw new IllegalStateException("Generate private key first!");
        }

        return MathUtils.modPow(otherPublicKey, privateKey, p);
    }

    // Getters
    public BigInteger getPublicKey() {
        return publicKey;
    }

    public BigInteger getP() {
        return p;
    }

    public BigInteger getG() {
        return g;
    }

    // Container for DH parameters
    public static class DHParameters {
        public final BigInteger p;
        public final BigInteger g;

        public DHParameters(BigInteger p, BigInteger g) {
            this.p = p;
            this.g = g;
        }

        @Override
        public String toString() {
            return "DH Parameters:\n  p=" + p.toString(16).substring(0, 32) + "...\n  g=" + g;
        }
    }
}