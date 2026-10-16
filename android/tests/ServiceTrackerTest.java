import dev.readb.companion.ServiceTracker;
public final class ServiceTrackerTest {
    private static void check(boolean ok) { if(!ok)throw new AssertionError(); }
    public static void main(String[] args) {
        ServiceTracker t=new ServiceTracker();
        long found=t.found("own-service");check(found>0);t.lost("own-service");check(!t.current("own-service",found));
        long first=t.found("own-service"),again=t.found("own-service");check(!t.current("own-service",first));check(t.current("own-service",again));
        t.reset();check(!t.current("own-service",again));
        for(int i=0;i<64;i++)check(t.found("service-"+i)>0);
        check(t.found("overflow")==0);check(!t.current("overflow",0));
        System.out.println("NSD stale callback checks passed");
    }
}
