package dev.readb.companion;

/** Small JSON boundary. Call from a worker; never pass credentials here. */
public final class NativeBridge {
    static { System.loadLibrary("readb_android_core"); }
    private NativeBridge() {}
    public static native String call(String request);
}
