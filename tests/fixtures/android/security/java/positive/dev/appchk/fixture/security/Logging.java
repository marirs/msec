package dev.appchk.fixture.security;

import android.util.Log;

/** Logging in a release build. */
final class Logging {
    static void all(String secret) {
        Log.d("Security", "token=" + secret);
        Log.v("Security", "verbose");
        System.out.println(secret);
    }
}
