package crypto;

import utils.MathUtils;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class RSA {

    public static class PublicKey {
        public final BigInteger e;
        public final BigInteger n;

        public PublicKey(BigInteger e, BigInteger n) {
            this.e = e;
            this.n = n;
        }

        @Override
        public String toString() {
            return "RSA Public Key:\n  e=" + e + "\n  n=" + n.toString(16).substring(0, 32) + "...";
        }
    }

    public static class PrivateKey {
        public final BigInteger d;
        public final BigInteger n;

        public PrivateKey(BigInteger d, BigInteger n) {
            this.d = d;
            this.n = n;
        }
    }

    public static class KeyPair {
        public final PublicKey publicKey;
        public final PrivateKey privateKey;

        public KeyPair(PublicKey pub, PrivateKey priv) {
            this.publicKey = pub;
            this.privateKey = priv;
        }
    }


     // Generating RSA key pair
     // By Using 512-bit keys for demonstration (faster than 2048-bit)
    public static KeyPair generateKeyPair(int bitLength) {
        System.out.println("Generating RSA keys (" + bitLength + "-bit)...");

        // Step 1: Generate two distinct primes p and q
        BigInteger p = MathUtils.generatePrime(bitLength / 2);
        BigInteger q = MathUtils.generatePrime(bitLength / 2);

        // Ensure p != q
        while (p.equals(q)) {
            q = MathUtils.generatePrime(bitLength / 2);
        }

        // Step 2: Compute n = p * q
        BigInteger n = p.multiply(q);

        // Step 3: Compute φ(n) = (p-1)(q-1)
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        // Step 4: Choose e (commonly 65537)
        BigInteger e = BigInteger.valueOf(65537);

        // Ensure gcd(e, phi) = 1
        while (!phi.gcd(e).equals(BigInteger.ONE)) {
            e = e.add(BigInteger.valueOf(2));
        }

        // Step 5: Compute d = e^(-1) mod φ(n)
        BigInteger d = MathUtils.modInverse(e, phi);

        System.out.println("RSA keys generated...");

        PublicKey publicKey = new PublicKey(e, n);
        PrivateKey privateKey = new PrivateKey(d, n);

        return new KeyPair(publicKey, privateKey);
    }

     // Simple hash function using SHA-256
    // (I used MessageDigest since it's just hashing, not crypto operations)
    public static byte[] simpleHash(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(data);
        } catch (NoSuchAlgorithmException e) {
            // Fallback to simple XOR-based hash if SHA-256 not available
            byte[] hash = new byte[32];
            for (int i = 0; i < data.length; i++) {
                hash[i % 32] ^= data[i];
            }
            return hash;
        }
    }
}