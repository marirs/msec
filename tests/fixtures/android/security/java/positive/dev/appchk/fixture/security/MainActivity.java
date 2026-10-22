package dev.appchk.fixture.security;

import android.app.Activity;
import android.os.Bundle;
import android.webkit.WebView;

/** Runs every positive case, so none is dead code. */
public class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        try {
            Crypto.all();
            CallShapes.all("AES/CBC/PKCS5Padding", true);
            Storage.all(this);
            // Called on the Activity itself: the reference names this class, not Context.
            openFileOutput("activity.txt", MODE_WORLD_READABLE).close();
            WebViews.all(new WebView(this));
            Logging.all("secret");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
