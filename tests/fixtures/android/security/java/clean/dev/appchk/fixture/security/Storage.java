package dev.appchk.fixture.security;

import android.content.Context;

/** Private files in the app's own storage. */
final class Storage {
    static void all(Context context) throws Exception {
        context.openFileOutput("private.txt", Context.MODE_PRIVATE).close();
        context.getSharedPreferences("prefs", Context.MODE_PRIVATE);
        context.getFilesDir();
    }
}
