package dev.readb.companion;
import java.util.HashMap;

/** Serialized by the service actor. A lost advertisement invalidates pending resolution. */
public final class ServiceTracker {
    private final HashMap<String,Long> present=new HashMap<>();
    private long revision;
    public long found(String name) {
        if(name==null || name.length()>253 || revision==Long.MAX_VALUE || (!present.containsKey(name) && present.size()>=64))return 0;
        long token=++revision;present.put(name,token);return token;
    }
    public void lost(String name) { present.remove(name); }
    public boolean current(String name,long token) { return token>0 && Long.valueOf(token).equals(present.get(name)); }
    public void reset() { present.clear(); }
}
