package dev.appchk.fixture.security;

import java.security.MessageDigest;
import java.util.Random;
import javax.crypto.Cipher;

/** Cryptography a scanner should report, each with its algorithm a constant at the call. */
final class Crypto {
    /** A compile-time constant: javac inlines it at the call. */
    static final String ECB = "AES/ECB/PKCS5Padding";

    static void all() throws Exception {
        Cipher.getInstance(ECB);
        // Through a local variable.
        String transformation = "DES/CBC/PKCS5Padding";
        Cipher.getInstance(transformation);
        // No mode: the provider's default applies.
        Cipher.getInstance("AES");
        // With a provider name: still the first argument.
        Cipher.getInstance("RC4", "AndroidOpenSSL");
        // RSA names ECB without meaning a block mode: not a broken mode.
        Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        MessageDigest.getInstance("MD5").digest(new byte[1]);
        MessageDigest.getInstance("SHA-1").digest(new byte[1]);
        new Random().nextInt();
        Math.random();
    }
}
