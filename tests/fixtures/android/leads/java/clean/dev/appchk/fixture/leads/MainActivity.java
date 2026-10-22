package dev.appchk.fixture.leads;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.view.WindowInsets;
import android.widget.TextView;
import com.android.billingclient.api.BillingClient;
import com.google.firebase.auth.FirebaseAuth;
import com.stripe.android.PaymentConfiguration;

/** Native UI, Play's billing beside Stripe, and sign-up with account deletion. */
public class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        TextView text = new TextView(this);
        text.setText("Leads");
        setContentView(text);
        text.setOnApplyWindowInsetsListener(
                new View.OnApplyWindowInsetsListener() {
                    @Override
                    public WindowInsets onApplyWindowInsets(View view, WindowInsets insets) {
                        return insets;
                    }
                });
        BillingClient.newBuilder(this);
        PaymentConfiguration.init(this, "pk_test_fixture");
        FirebaseAuth auth = FirebaseAuth.getInstance();
        auth.createUserWithEmailAndPassword("user@example.com", "x");
        auth.getCurrentUser().delete();
    }
}
