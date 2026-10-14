package dev.appchk.fixture.code;

/** Redefines classes.dex's Config: Android loads that copy, so this one is shadowed. */
public final class Config {
    private Config() {}

    public static String greeting() {
        return "shadowed";
    }
}
