package dev.appchk.fixture.security;

import javax.crypto.Cipher;

/** Calls whose argument is not a constant at the call site: none may be reported as one. */
final class CallShapes {
    /** A field that is not a compile-time constant. */
    static String configured = "DES/ECB/PKCS5Padding";

    static void all(String parameter, boolean modern) throws Exception {
        // A parameter.
        Cipher.getInstance(parameter);
        // Two constants merged from two branches: neither is the argument on every path.
        String merged = modern ? "AES/GCM/NoPadding" : "Blowfish/ECB/NoPadding";
        Cipher.getInstance(merged);
        // Read from a field.
        Cipher.getInstance(configured);
    }
}
