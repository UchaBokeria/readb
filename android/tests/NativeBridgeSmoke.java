import dev.readb.companion.NativeBridge;

public final class NativeBridgeSmoke {
    private static void contains(String result, String expected) {
        if (!result.contains(expected)) throw new AssertionError(result);
    }
    public static void main(String[] args) {
        contains(NativeBridge.call(null), "invalid_request");
        contains(NativeBridge.call("x".repeat(9000)), "request_too_large");
        contains(NativeBridge.call("{\"op\":\"create\",\"epoch\":\"reporter-jvm\",\"now\":0}"), "\"handle\":1");
        contains(NativeBridge.call("{\"op\":\"port\",\"handle\":1,\"now\":1,\"port\":40000}"), "\"ok\":true");
        contains(NativeBridge.call("{\"op\":\"close\",\"handle\":1}"), "\"ok\":true");
        contains(NativeBridge.call("{\"op\":\"network\",\"handle\":1,\"now\":2}"), "unknown_reporter");
        contains(NativeBridge.call("😀"), "invalid_request");
        System.out.println("JNI smoke passed");
    }
}
