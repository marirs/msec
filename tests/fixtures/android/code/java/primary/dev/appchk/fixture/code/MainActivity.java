package dev.appchk.fixture.code;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;

/** A platform subclass, an inner class, and a lambda (which d8 turns into a synthetic class). */
public class MainActivity extends Activity {
    private final Runnable greeter = () -> Log.i("fixture", Config.greeting());

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        new Listener().onClick(null);
        greeter.run();
        new TopLevelUser().use();
    }

    /** Compiled as {@code MainActivity$Listener}. */
    class Listener implements View.OnClickListener {
        @Override
        public void onClick(View view) {
            Log.i("fixture", Config.endpoint());
        }
    }
}
