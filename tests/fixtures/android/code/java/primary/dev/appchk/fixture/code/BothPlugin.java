package dev.appchk.fixture.code;

/** Two interfaces: one from the platform, one from the app. */
public abstract class BothPlugin implements Runnable, Plugin {
    @Override
    public String name() {
        return "both";
    }
}
