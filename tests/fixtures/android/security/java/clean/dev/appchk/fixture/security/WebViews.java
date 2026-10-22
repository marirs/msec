package dev.appchk.fixture.security;

import android.webkit.WebSettings;
import android.webkit.WebView;

/** A WebView with file and content access off, Safe Browsing on, and no bridge. */
final class WebViews {
    static void all(WebView view) {
        WebSettings settings = view.getSettings();
        settings.setAllowFileAccess(false);
        settings.setAllowContentAccess(false);
        settings.setSafeBrowsingEnabled(true);
        view.setWebViewClient(new SafeClient());
        WebView.setWebContentsDebuggingEnabled(false);
    }
}
