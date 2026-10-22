package dev.appchk.fixture.leads;

import android.app.Activity;
import android.os.Bundle;
import android.webkit.WebView;
import com.google.firebase.auth.FirebaseAuth;
import com.stripe.android.PaymentConfiguration;

/** A website in a WebView, sign-up without deletion, and Stripe without Play's billing. */
public class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        WebView page = new WebView(this);
        page.loadUrl("https://shop.example.com/");
        setContentView(page);
        PaymentConfiguration.init(this, "pk_test_fixture");
        FirebaseAuth.getInstance().createUserWithEmailAndPassword("user@example.com", "x");
    }
}
