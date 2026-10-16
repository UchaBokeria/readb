package dev.readb.companion;

import android.app.*;
import android.content.*;
import android.net.*;
import android.net.nsd.*;
import android.os.*;
import android.provider.Settings;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import org.json.JSONObject;

/** SDK glue only. Rust owns report timing/order. All state lives on one worker. */
public final class ReportService extends Service {
    private final AtomicBoolean closed=new AtomicBoolean(false);
    private HandlerThread thread;
    private Handler actor;
    private final ExecutorService network=Executors.newSingleThreadExecutor();
    private volatile HttpURLConnection connection;
    private long handle, discoveryGeneration, seenGeneration;
    private JSONObject profile;
    private NsdManager nsd;
    private NsdManager.DiscoveryListener discovery;
    private ConnectivityManager connectivity;
    private ConnectivityManager.NetworkCallback networks;
    private boolean inflight, discovering;
    private String ownService;
    private final ServiceTracker services=new ServiceTracker();
    private final Object connectionLock=new Object();
    private final Runnable wake=this::tick;
    private final Runnable scan=new Runnable() { public void run() { if(closed.get()) return; discover(); actor.postDelayed(this,20000); } };
    private long now() { return SystemClock.elapsedRealtime(); }
    private void post(Runnable r) { if(!closed.get() && actor!=null) actor.post(()->{if(!closed.get()) r.run();}); }
    private void status(String text) { createDeviceProtectedStorageContext().getSharedPreferences("status",0).edit().putString("report_message",text).apply(); }
    private JSONObject call(JSONObject r) throws Exception {
        JSONObject response=new JSONObject(NativeBridge.call(r.toString()));
        if(!response.optBoolean("ok")) throw new IllegalStateException("report_core_rejected");
        return response;
    }
    private JSONObject request(String op) throws Exception { return new JSONObject().put("op",op).put("handle",handle).put("now",now()); }
    @Override public void onCreate() {
        super.onCreate();
        ProfileStore.serviceStarting(this);
        NotificationManager nm=getSystemService(NotificationManager.class);
        nm.createNotificationChannel(new NotificationChannel("readb-report","readb reporting",NotificationManager.IMPORTANCE_LOW));
        PendingIntent open=PendingIntent.getActivity(this,1,new Intent(this,MainActivity.class),PendingIntent.FLAG_IMMUTABLE);
        startForeground(1,new Notification.Builder(this,"readb-report").setSmallIcon(android.R.drawable.stat_notify_sync).setContentTitle("readb")
            .setContentText("Keeping your server informed of this device's secure ADB endpoint").setContentIntent(open).build());
        thread=new HandlerThread("readb-state");thread.start();actor=new Handler(thread.getLooper());
        nsd=getSystemService(NsdManager.class);connectivity=getSystemService(ConnectivityManager.class);
        post(()-> {
            try {
                if(!createDeviceProtectedStorageContext().getSharedPreferences("status",0).getBoolean("report_enabled",false)) { stopSelf();return; }
                profile=ProfileStore.load(this);
                handle=call(new JSONObject().put("op","create").put("epoch",UUID.randomUUID().toString()).put("now",now())).getLong("handle");
                if(closed.get())return;
                networks=new ConnectivityManager.NetworkCallback() {
                    public void onAvailable(Network n) { changed(); }
                    public void onLost(Network n) { changed(); }
                    public void onLinkPropertiesChanged(Network n,LinkProperties p) { changed(); }
                    private void changed() { post(()-> { try { call(request("network")); tick(); } catch(Exception e) { status("Network event unavailable. Retrying."); } }); }
                };
                connectivity.registerNetworkCallback(new NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build(),networks);
                tick();actor.post(scan);
            } catch(Exception e) { status("Enrollment unavailable. Open readb to check setup.");stopSelf(); }
        });
    }
    private JSONObject observed() throws Exception {
        boolean quest=Build.MANUFACTURER.equalsIgnoreCase("Oculus") || Build.MANUFACTURER.equalsIgnoreCase("Meta");
        boolean keyguard=getSystemService(KeyguardManager.class).isKeyguardLocked();
        boolean secure=checkSelfPermission("android.permission.WRITE_SECURE_SETTINGS")==android.content.pm.PackageManager.PERMISSION_GRANTED;
        return new JSONObject().put("credential_storage_unlocked",getSystemService(UserManager.class).isUserUnlocked())
            .put("screen_lock",quest?"unknown":(keyguard?"locked":"unlocked"))
            .put("vpn_active",createDeviceProtectedStorageContext().getSharedPreferences("status",0).getBoolean("vpn_active",false))
            .put("notifications",getSystemService(NotificationManager.class).areNotificationsEnabled()?"granted":"denied")
            .put("discovery",discovering?"granted":"unknown").put("secure_settings",secure?"granted":"denied");
    }
    private int battery() {
        Intent i=registerReceiver(null,new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
        int level=i==null?-1:i.getIntExtra("level",-1),scale=i==null?0:i.getIntExtra("scale",0);
        return level<0 || scale<=0 ? -1 : (int)Math.min(100,100L*level/scale);
    }
    private void tick() {
        if(closed.get() || handle==0) return;
        actor.removeCallbacks(wake);
        if(inflight) return;
        try {
            JSONObject result=call(request("poll").put("battery",battery()).put("observed",observed()));
            JSONObject report=result.optJSONObject("report");
            if(report==null) { schedule(result.getLong("next_due"));return; }
            inflight=true;
            network.execute(()-> {
                boolean success=false;
                try { success=send(report); } finally {
                    final boolean accepted=success;
                    post(()-> {
                        inflight=false;
                        try {
                            JSONObject completed=call(request("complete").put("sequence",report.getLong("sequence")).put("success",accepted));
                            schedule(completed.getLong("next_due"));
                        } catch(Exception e) { status("Report state unavailable. Restart readb.");stopSelf(); }
                    });
                }
            });
        } catch(Exception e) { status("Report worker unavailable. Restart readb.");stopSelf(); }
    }
    private void schedule(long due) { if(!closed.get()) actor.postDelayed(wake,Math.max(1,due-now())); }
    private Network privateNetwork() throws Exception {
        if(closed.get() || !createDeviceProtectedStorageContext().getSharedPreferences("status",0).getBoolean("vpn_active",false)) return null;
        InetAddress address=InetAddress.getByName(profile.getString("device_address"));
        for(Network n:connectivity.getAllNetworks()) {
            NetworkCapabilities cap=connectivity.getNetworkCapabilities(n);LinkProperties link=connectivity.getLinkProperties(n);
            if(cap==null || link==null || !cap.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue;
            for(LinkAddress a:link.getLinkAddresses()) if(a.getAddress().equals(address)) return n;
        }
        return null;
    }
    private boolean send(JSONObject report) {
        HttpURLConnection c=null;
        try {
            Network vpn=privateNetwork();
            if(vpn==null) { status("Waiting for the private VPN. No report sent outside it.");return false; }
            URL url=new URL("http://"+profile.getString("server_peer")+":"+profile.getInt("server_port")+"/v2/"+profile.getString("device_id"));
            synchronized(connectionLock) {
                if(closed.get())return false;
                c=(HttpURLConnection)vpn.openConnection(url);connection=c;
            }
            c.setInstanceFollowRedirects(false);c.setConnectTimeout(8000);c.setReadTimeout(15000);c.setRequestMethod("POST");
            c.setRequestProperty("Authorization","Bearer "+profile.getString("token"));c.setRequestProperty("Content-Type","application/json");c.setDoOutput(true);
            byte[] data=report.toString().getBytes(StandardCharsets.UTF_8);c.setFixedLengthStreamingMode(data.length);
            if(closed.get())return false;
            try(java.io.OutputStream out=c.getOutputStream()) { if(closed.get())return false;out.write(data); }
            int code=c.getResponseCode();
            if(code!=200) { status(code==403?"Server refused enrollment. Check credentials.":code==409?"Server refused report ordering. Check setup.":"Server unavailable. Retrying.");return false; }
            byte[] response;
            try(java.io.InputStream in=c.getInputStream()) { response=in.readNBytes(4097); }
            if(response.length>4096) { status("Server response invalid. Retrying.");return false; }
            JSONObject result=new JSONObject(new String(response,StandardCharsets.UTF_8));
            if(!result.optBoolean("ok")) return false;
            createDeviceProtectedStorageContext().getSharedPreferences("status",0).edit().putLong("last_report_epoch",System.currentTimeMillis()).apply();
            status(result.optBoolean("connected")?"Server connected to pinned secure ADB.":"Reported. Secure ADB is not connected yet.");return true;
        } catch(Exception e) { status("Private link unavailable. Retrying automatically.");return false; }
        finally { if(c!=null)c.disconnect();synchronized(connectionLock){if(connection==c)connection=null;} }
    }
    private boolean isOwnAddress(InetAddress address) {
        if(address==null) return false;
        for(Network n:connectivity.getAllNetworks()) { LinkProperties p=connectivity.getLinkProperties(n);if(p!=null)for(LinkAddress a:p.getLinkAddresses())if(a.getAddress().equals(address))return true; }
        return false;
    }
    private void port(Integer p) {
        try { call(request("port").put("port",p==null?JSONObject.NULL:p));tick(); }
        catch(Exception e) { status("TLS discovery update unavailable."); }
    }
    private void discover() {
        if(closed.get())return;
        final long epoch=++discoveryGeneration;
        services.reset();
        if(discovery!=null)try{nsd.stopServiceDiscovery(discovery);}catch(RuntimeException ignored){}
        discovering=false;
        discovery=new NsdManager.DiscoveryListener() {
            private void current(Runnable r) { post(()->{if(discoveryGeneration==epoch)r.run();}); }
            public void onDiscoveryStarted(String type){current(()->discovering=true);}
            public void onDiscoveryStopped(String type){current(()->discovering=false);}
            public void onStartDiscoveryFailed(String type,int error){current(()->{discovering=false;port(null);status("Discovery denied or unavailable. Check permissions.");});}
            public void onStopDiscoveryFailed(String type,int error){current(()->discovering=false);}
            public void onServiceLost(NsdServiceInfo info){current(()->{services.lost(info.getServiceName());if(info.getServiceName().equals(ownService)){ownService=null;port(null);}});}
            public void onServiceFound(NsdServiceInfo info) {
                current(()-> {
                    if(!info.getServiceType().contains("_adb-tls-connect._tcp"))return;
                    final String name=info.getServiceName();final long token=services.found(name);if(token==0)return;
                    nsd.resolveService(info,new NsdManager.ResolveListener() {
                        public void onResolveFailed(NsdServiceInfo i,int error){ }
                        public void onServiceResolved(NsdServiceInfo i){current(()->{if(services.current(name,token) && name.equals(i.getServiceName()) && isOwnAddress(i.getHost()) && i.getPort()>=1024 && i.getPort()<=65535){ownService=i.getServiceName();seenGeneration=epoch;port(i.getPort());}});}
                    });
                });
            }
        };
        try {
            NetworkRequest wifi=new NetworkRequest.Builder().addTransportType(NetworkCapabilities.TRANSPORT_WIFI).addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build();
            nsd.discoverServices("_adb-tls-connect._tcp",NsdManager.PROTOCOL_DNS_SD,wifi,getMainExecutor(),discovery);
            actor.postDelayed(()->{if(!closed.get() && discoveryGeneration==epoch && seenGeneration!=epoch){ownService=null;port(null);}},12000);
        } catch(RuntimeException e) { port(null);status("Discovery unavailable. Check permissions."); }
    }
    @Override public int onStartCommand(Intent i,int flags,int id) { return START_STICKY; }
    @Override public IBinder onBind(Intent i) { return null; }
    @Override public void onDestroy() {
        if(!closed.compareAndSet(false,true))return;
        synchronized(connectionLock) { HttpURLConnection c=connection;if(c!=null)c.disconnect(); }
        network.shutdownNow();
        CountDownLatch actorClosed=new CountDownLatch(1);
        if(actor!=null) {
            actor.removeCallbacksAndMessages(null);
            actor.post(()-> {
                try {
                    discoveryGeneration++;
                    if(networks!=null)try{connectivity.unregisterNetworkCallback(networks);}catch(RuntimeException ignored){}
                    if(discovery!=null)try{nsd.stopServiceDiscovery(discovery);}catch(RuntimeException ignored){}
                    if(handle!=0)NativeBridge.call("{\"op\":\"close\",\"handle\":"+handle+"}");
                } finally { thread.quitSafely();actorClosed.countDown(); }
            });
        } else actorClosed.countDown();
        Thread cleanup=new Thread(()-> {
            try {
                boolean stopped=network.awaitTermination(60,TimeUnit.SECONDS) && actorClosed.await(10,TimeUnit.SECONDS);
                if(stopped)ProfileStore.serviceStopped(this);
                else status("Report cleanup is still pending. Restart readb before changing enrollment.");
            } catch(InterruptedException e) { Thread.currentThread().interrupt(); }
        },"readb-network-cleanup");cleanup.setDaemon(true);cleanup.start();
        super.onDestroy();
    }
}
