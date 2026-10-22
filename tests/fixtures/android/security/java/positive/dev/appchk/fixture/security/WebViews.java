package dev.appchk.fixture.security;

import android.webkit.WebSettings;
import android.webkit.WebView;

/** A WebView with a JavaScript bridge, relaxed file access, debugging and Safe Browsing off. */
final class WebViews {
    static void all(WebView view) {
        WebSettings settings = view.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setAllowFileAccessFromFileURLs(true);
        settings.setAllowUniversalAccessFromFileURLs(true);
        settings.setAllowFileAccess(true);
        settings.setAllowContentAccess(true);
        settings.setSafeBrowsingEnabled(false);
        view.addJavascriptInterface(new Bridge(), "bridge");
        view.setWebViewClient(new InsecureClient());
        WebView.setWebContentsDebuggingEnabled(true);
    }

    /** What the page may call. */
    static final class Bridge {
        @android.webkit.JavascriptInterface
        public String token() {
            return "token";
        }
    }
}
