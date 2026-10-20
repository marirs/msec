package android.graphics;

import java.io.OutputStream;

/**
 * Compile-time stand-in for the framework class, declaring Picture.writeToStream, which Android
 * removed from the public SDK in API 29. Only javac sees it; the stub is never packaged.
 */
public class Picture {
    public void writeToStream(OutputStream stream) {
        throw new RuntimeException("stub");
    }
}
