package dev.readb.companion;

import android.content.Context;
import android.net.*;
import android.net.nsd.*;
import android.os.*;
import android.provider.Settings;

/** Foreground-only, read-only observation. Never enables debugging or starts a VPN. */
final class DebugEndpointObserver {
 private final Context context;
 private final Handler actor=new Handler(Looper.getMainLooper());
 private final EndpointState endpoint=new EndpointState();
 private final ServiceTracker services=new ServiceTracker();
 private final NsdManager nsd;
 private final ConnectivityManager networks;
 private NsdManager.DiscoveryListener listener;
 private long generation;
 private boolean running;
 private String own;
 private final Runnable scan=new Runnable(){public void run(){if(!running)return;discover();actor.postDelayed(this,20000);}};
 DebugEndpointObserver(Context c){context=c;nsd=c.getSystemService(NsdManager.class);networks=c.getSystemService(ConnectivityManager.class);}
 Boolean enabled(){try {int v=Settings.Global.getInt(context.getContentResolver(),"adb_wifi_enabled",-1);return v<0?null:v==1;}catch(RuntimeException e){return null;}}
 Integer port(){if(Boolean.FALSE.equals(enabled()))endpoint.disabled();return endpoint.current(SystemClock.elapsedRealtime());}
 long observedEpoch(){long now=SystemClock.elapsedRealtime();return endpoint.current(now)==null?0:System.currentTimeMillis()-(now-endpoint.observedAt());}
 void start(){if(running)return;running=true;actor.post(scan);}
 void stop(){running=false;++generation;actor.removeCallbacksAndMessages(null);stopDiscovery();services.reset();endpoint.disabled();}
 private void stopDiscovery(){if(listener!=null)try{nsd.stopServiceDiscovery(listener);}catch(RuntimeException ignored){}listener=null;}
 private boolean local(java.net.InetAddress address){
  if(address==null)return false;
  try{for(Network n:networks.getAllNetworks()){LinkProperties p=networks.getLinkProperties(n);if(p!=null)for(LinkAddress a:p.getLinkAddresses())if(a.getAddress().equals(address))return true;}}catch(RuntimeException ignored){}
  return false;
 }
 private void discover(){
  final long epoch=++generation;stopDiscovery();services.reset();
  if(Boolean.FALSE.equals(enabled())){endpoint.disabled();return;}
  listener=new NsdManager.DiscoveryListener(){
   private void current(Runnable r){actor.post(()->{if(running&&generation==epoch)r.run();});}
   public void onDiscoveryStarted(String t){}
   public void onDiscoveryStopped(String t){}
   public void onStartDiscoveryFailed(String t,int e){current(endpoint::disabled);}
   public void onStopDiscoveryFailed(String t,int e){}
   public void onServiceLost(NsdServiceInfo i){current(()->{services.lost(i.getServiceName());if(i.getServiceName().equals(own)){own=null;endpoint.disabled();}});}
   public void onServiceFound(NsdServiceInfo i){current(()->{
    if(!i.getServiceType().contains("_adb-tls-connect._tcp"))return;
    final String name=i.getServiceName();final long token=services.found(name);if(token==0)return;
    try{nsd.resolveService(i,new NsdManager.ResolveListener(){
     public void onResolveFailed(NsdServiceInfo value,int e){}
     public void onServiceResolved(NsdServiceInfo value){current(()->{if(services.current(name,token)&&name.equals(value.getServiceName())&&local(value.getHost())&&value.getPort()>=1024&&value.getPort()<=65535){own=name;endpoint.seen(value.getPort(),SystemClock.elapsedRealtime());}});}
    });}catch(RuntimeException ignored){}
   });}
  };
  try{
   NetworkRequest wifi=new NetworkRequest.Builder().addTransportType(NetworkCapabilities.TRANSPORT_WIFI).addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build();
   nsd.discoverServices("_adb-tls-connect._tcp",NsdManager.PROTOCOL_DNS_SD,wifi,context.getMainExecutor(),listener);
  }catch(RuntimeException e){endpoint.disabled();}
 }
}
