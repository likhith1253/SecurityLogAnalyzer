package com.sla.util;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Salted PBKDF2 password hashing. Stored format:
 * {@code pbkdf2$<iterations>$<base64 salt>$<base64 hash>}.
 */
public final class PasswordHasher {
    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int ITERATIONS = 120_000;
    private static final int SALT_BYTES = 16;
    private static final int KEY_BITS = 256;
    private static final SecureRandom RANDOM = new SecureRandom();

    private PasswordHasher() {
    }

    public static String hash(String password) {
        byte[] salt = new byte[SALT_BYTES];
        RANDOM.nextBytes(salt);
        byte[] hash = derive(password, salt, ITERATIONS);
        return "pbkdf2$" + ITERATIONS + "$"
            + Base64.getEncoder().encodeToString(salt) + "$"
            + Base64.getEncoder().encodeToString(hash);
    }

    public static boolean isHashed(String stored) {
        return stored != null && stored.startsWith("pbkdf2$");
    }

    /** Returns true if {@code password} matches {@code stored}; compares in constant time. */
    public static boolean verify(String password, String stored) {
        if (!isHashed(stored)) {
            return false;
        }
        try {
            String[] parts = stored.split("[$]");
            if (parts.length != 4) {
                return false;
            }
            int iterations = Integer.parseInt(parts[1]);
            byte[] salt = Base64.getDecoder().decode(parts[2]);
            byte[] expected = Base64.getDecoder().decode(parts[3]);
            byte[] actual = derive(password, salt, iterations);
            return MessageDigest.isEqual(expected, actual);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private static byte[] derive(String password, byte[] salt, int iterations) {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, KEY_BITS);
        try {
            return SecretKeyFactory.getInstance(ALGORITHM).generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("PBKDF2 not available", e);
        } finally {
            spec.clearPassword();
        }
    }

    /** Small CLI helper: {@code java com.sla.util.PasswordHasher <password>} prints a hash for users.csv. */
    public static void main(String[] args) {
        if (args.length != 1) {
            System.err.println("Usage: java com.sla.util.PasswordHasher <password>");
            System.exit(2);
        }
        System.out.println(hash(args[0]));
    }
}
