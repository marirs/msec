package dev.appchk.fixture.code;

import android.accounts.Account;
import android.accounts.AccountManager;
import android.app.Activity;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Canvas;
import android.graphics.Picture;
import android.os.AsyncTask;
import android.os.Build;
import android.os.PowerManager;
import java.io.OutputStream;

/**
 * Calls Google Play flags on upload: window colours Android 15 deprecated for edge-to-edge, a
 * decode without BitmapFactory.Options, a deprecated method reached through an app class, a
 * subclass of a deprecated class, a partial wake lock held without a timeout, and sign-in (an
 * account added) with no Restore Credentials or Block Store call. Also calls APIs
 * Android removed from the public SDK (compiled against the stubs in java/stubs), with and
 * without a version check in the calling method.
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

    /** Canvas.save(int), removed in API 28, with no version check. */
    static int saveLayer(Canvas canvas) {
        return canvas.save(1);
    }

    /** Canvas.save(int) again, behind a version check. */
    static int saveChecked(Canvas canvas) {
        if (Build.VERSION.SDK_INT < 28) {
            return canvas.save(1);
        }
        return canvas.save();
    }

    /** Picture.writeToStream, removed in API 29, called only behind a version check. */
    static void record(Picture picture, OutputStream stream) {
        if (Build.VERSION.SDK_INT < 29) {
            picture.writeToStream(stream);
        }
    }

    /** A partial wake lock acquired without a timeout: held until released. */
    static void hold(PowerManager power) {
        power.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "fixture:hold").acquire();
    }

    /** Signs the user in by adding an account; nothing restores it on a new device. */
    static boolean signIn(AccountManager accounts, Account account) {
        return accounts.addAccountExplicitly(account, null, null);
    }

    /** AsyncTask is deprecated in API 30. */
    static final class Loader extends AsyncTask<Void, Void, Void> {
        @Override
        protected Void doInBackground(Void... nothing) {
            return null;
        }
    }
}
