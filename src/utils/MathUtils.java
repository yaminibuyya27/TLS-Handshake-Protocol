package utils;

import java.math.BigInteger;
import java.security.SecureRandom;

public class MathUtils {
    private static final SecureRandom random = new SecureRandom();

     // Manual implementation of modular exponentiation
     // Computes (base^exponent) mod modulus
     // Uses repeated squaring algorithm
    public static BigInteger modPow(BigInteger base, BigInteger exponent, BigInteger modulus) {
        if (modulus.equals(BigInteger.ONE)) {
            return BigInteger.ZERO;
        }

        BigInteger result = BigInteger.ONE;
        base = base.mod(modulus);

        while (exponent.compareTo(BigInteger.ZERO) > 0) {
            // If exponent is odd, multiply base with result
            if (exponent.testBit(0)) {
                result = (result.multiply(base)).mod(modulus);
            }
            // exponent = exponent / 2
            exponent = exponent.shiftRight(1);
            // base = base^2
            base = (base.multiply(base)).mod(modulus);
        }

        return result;
    }


     // Miller-Rabin primality test
     // Tests if a number is probably prime
    public static boolean isProbablePrime(BigInteger n, int iterations) {
        if (n.compareTo(BigInteger.valueOf(2)) < 0) {
            return false;
        }
        if (n.equals(BigInteger.valueOf(2)) || n.equals(BigInteger.valueOf(3))) {
            return true;
        }
        if (n.mod(BigInteger.valueOf(2)).equals(BigInteger.ZERO)) {
            return false;
        }

        // Write n-1 as 2^r * d
        BigInteger d = n.subtract(BigInteger.ONE);
        int r = 0;
        while (d.mod(BigInteger.valueOf(2)).equals(BigInteger.ZERO)) {
            d = d.divide(BigInteger.valueOf(2));
            r++;
        }

        // Witness loop
        for (int i = 0; i < iterations; i++) {
            BigInteger a = randomBigInteger(BigInteger.valueOf(2), n.subtract(BigInteger.valueOf(2)));
            BigInteger x = modPow(a, d, n);

            if (x.equals(BigInteger.ONE) || x.equals(n.subtract(BigInteger.ONE))) {
                continue;
            }

            boolean continueWitness = false;
            for (int j = 0; j < r - 1; j++) {
                x = modPow(x, BigInteger.valueOf(2), n);
                if (x.equals(n.subtract(BigInteger.ONE))) {
                    continueWitness = true;
                    break;
                }
            }

            if (!continueWitness) {
                return false;
            }
        }

        return true;
    }


     // Generate a random prime number of specified bit length
    public static BigInteger generatePrime(int bitLength) {
        BigInteger prime;
        do {
            prime = new BigInteger(bitLength, random);
            // Ensure it's odd
            prime = prime.setBit(0);
            // Ensure high bit is set (full bit length)
            prime = prime.setBit(bitLength - 1);
        } while (!isProbablePrime(prime, 10));

        return prime;
    }


     // Extended Euclidean Algorithm to find modular inverse
    public static BigInteger modInverse(BigInteger a, BigInteger m) {
        BigInteger m0 = m;
        BigInteger x0 = BigInteger.ZERO;
        BigInteger x1 = BigInteger.ONE;

        if (m.equals(BigInteger.ONE)) {
            return BigInteger.ZERO;
        }

        while (a.compareTo(BigInteger.ONE) > 0) {
            BigInteger q = a.divide(m);
            BigInteger t = m;

            m = a.mod(m);
            a = t;
            t = x0;

            x0 = x1.subtract(q.multiply(x0));
            x1 = t;
        }

        if (x1.compareTo(BigInteger.ZERO) < 0) {
            x1 = x1.add(m0);
        }

        return x1;
    }


     // Generate random BigInteger in range [min, max]
    public static BigInteger randomBigInteger(BigInteger min, BigInteger max) {
        BigInteger range = max.subtract(min).add(BigInteger.ONE);
        BigInteger result;
        do {
            result = new BigInteger(range.bitLength(), random);
        } while (result.compareTo(range) >= 0);

        return result.add(min);
    }
}