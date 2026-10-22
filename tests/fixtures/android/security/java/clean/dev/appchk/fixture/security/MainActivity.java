package dev.appchk.fixture.security;

import android.app.Activity;
import android.os.Bundle;
import android.webkit.WebView;

/** Runs every negative case. */
public class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        try {
            Crypto.all();
            Storage.all(this);
            WebViews.all(new WebView(this));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
