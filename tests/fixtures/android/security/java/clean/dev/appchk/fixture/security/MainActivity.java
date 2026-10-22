package dev.appchk.fixture.security;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.view.WindowInsets;
import android.webkit.WebView;

/** Runs every negative case, and handles window insets as an app targeting API 35+ must. */
public class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        try {
            Crypto.all();
            Storage.all(this);
            WebViews.all(new WebView(this));
            getWindow().getDecorView().setOnApplyWindowInsetsListener(
                    new View.OnApplyWindowInsetsListener() {
                        @Override
                        public WindowInsets onApplyWindowInsets(View view, WindowInsets insets) {
                            return insets;
                        }
                    });
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
