package dev.appchk.fixture.security;

import java.security.MessageDigest;
import java.security.SecureRandom;
import javax.crypto.Cipher;

/** The same cryptography done safely: AES-GCM, RSA with OAEP, SHA-256, SecureRandom. */
final class Crypto {
    static void all() throws Exception {
        Cipher.getInstance("AES/GCM/NoPadding");
        Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        MessageDigest.getInstance("SHA-256").digest(new byte[1]);
        new SecureRandom().nextInt();
    }
}
