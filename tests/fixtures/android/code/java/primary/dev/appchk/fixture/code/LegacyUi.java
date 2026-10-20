package dev.appchk.fixture.code;

import android.app.Activity;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.os.AsyncTask;

/**
 * Calls Google Play flags on upload: window colours Android 15 deprecated for edge-to-edge, a
 * decode without BitmapFactory.Options, a deprecated method reached through an app class, and a
 * subclass of a deprecated class.
 */
final class LegacyUi {
    private LegacyUi() {}

    static void colour(Activity activity) {
        activity.getWindow().setStatusBarColor(0xff000000);
        activity.getWindow().setNavigationBarColor(0xff000000);
    }

    static Bitmap thumbnail(String path) {
        return BitmapFactory.decodeFile(path);
    }

    /** Activity.getFragmentManager, deprecated in API 28, named through MainActivity. */
    static Object fragments(MainActivity activity) {
        return activity.getFragmentManager();
    }

    /** AsyncTask is deprecated in API 30. */
    static final class Loader extends AsyncTask<Void, Void, Void> {
        @Override
        protected Void doInBackground(Void... nothing) {
            return null;
        }
    }
}
