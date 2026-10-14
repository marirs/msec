package dev.appchk.fixture.code;

/**
 * Strings that exercise DEX string encoding (MUTF-8) and ordering. java/secondary redefines
 * this class; Android loads this copy, from classes.dex.
 */
public final class Config {
    private Config() {}

    public static String greeting() {
        return "hello";
    }

    public static String endpoint() {
        return "https://api.example.org/v1";
    }

    /** U+0000 is encoded as the two bytes C0 80. */
    public static String withNul() {
        return "a\u0000b";
    }

    /** A two-byte sequence. */
    public static String accented() {
        return "café";
    }

    /** A three-byte sequence that sorts after surrogates in UTF-16 order. */
    public static String privateUse() {
        return "";
    }

    /** A supplementary character: a surrogate pair, each half its own three-byte sequence. */
    public static String emoji() {
        return "😀";
    }

    /** A lone surrogate: valid in DEX, not representable in UTF-8. */
    public static String loneSurrogate() {
        return "\ud800";
    }
}
