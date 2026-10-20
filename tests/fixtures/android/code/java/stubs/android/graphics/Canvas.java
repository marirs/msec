package android.graphics;

/**
 * Compile-time stand-in for the framework class, declaring Canvas.save(int), which Android
 * removed from the public SDK in API 28 (android.jar no longer has it). Only javac sees it:
 * d8 and R8 compile the fixture against android.jar, and the stub is never packaged.
 */
public class Canvas {
    public int save() {
        throw new RuntimeException("stub");
    }

    public int save(int saveFlags) {
        throw new RuntimeException("stub");
    }
}
