package dev.appchk.fixture.security;

import android.content.Context;
import android.os.Environment;

/** Files other apps may read or write. */
final class Storage {
    @SuppressWarnings("deprecation")
    static void all(Context context) throws Exception {
        context.openFileOutput("shared.txt", Context.MODE_WORLD_READABLE).close();
        context.getSharedPreferences("prefs", Context.MODE_WORLD_WRITEABLE);
        Environment.getExternalStorageDirectory();
        context.getExternalFilesDir(null);
    }
}
