package crypto;

import java.math.BigInteger;

public class KDF {


     //Derive encryption key from shared secret
    public static byte[] deriveKey(BigInteger sharedSecret, int iterations, int keyLength) {
        // Convert shared secret to bytes
        byte[] secret = sharedSecret.toByteArray();

        // Iteratively hash
        byte[] key = secret;
        for (int i = 0; i < iterations; i++) {
            key = RSA.simpleHash(key);
        }

        // Truncate or extend to desired key length
        byte[] derivedKey = new byte[keyLength];
        System.arraycopy(key, 0, derivedKey, 0, Math.min(key.length, keyLength));
        return derivedKey;
    }


     //Derive multiple keys from shared secret and Returns: [encryption key, MAC key]
    public static byte[][] deriveSessionKeys(BigInteger sharedSecret) {
        // Derive 32-byte master key
        byte[] masterKey = deriveKey(sharedSecret, 10000, 32);

        // Split into encryption key (16 bytes) and MAC key (16 bytes)
        byte[] encKey = new byte[16];
        byte[] macKey = new byte[16];

        System.arraycopy(masterKey, 0, encKey, 0, 16);
        System.arraycopy(masterKey, 16, macKey, 0, 16);

        return new byte[][] { encKey, macKey };
    }
}