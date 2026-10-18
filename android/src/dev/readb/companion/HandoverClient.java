package dev.readb.companion;
import android.content.*;
import android.os.*;
import dev.readb.handover.*;
import java.io.IOException;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import org.json.JSONObject;

/** Explicit UI-callable migration only. No startup hook, enrollment overwrite or service activation. */
public final class HandoverClient {
 private static final AtomicBoolean ACTIVE=new AtomicBoolean();
 private HandoverClient(){}
 public static CompletableFuture<JSONObject> importFrom(Context original,String source){
  CompletableFuture<JSONObject> result=new CompletableFuture<>();
  if(!HandoverAndroid.source(source)||!ACTIVE.compareAndSet(false,true)){result.completeExceptionally(new IOException("handover_busy_or_source_invalid"));return result;}
  Context context=original.getApplicationContext();Handler main=new Handler(Looper.getMainLooper());CompletableFuture<IBinder> connected=new CompletableFuture<>();AtomicBoolean bound=new AtomicBoolean();
  ServiceConnection connection=new ServiceConnection(){
   public void onServiceConnected(ComponentName name,IBinder binder){if(!name.equals(new ComponentName(source,source+".HandoverService")))connected.completeExceptionally(new SecurityException("handover_component_rejected"));else connected.complete(binder);}
   public void onServiceDisconnected(ComponentName name){connected.completeExceptionally(new IOException("handover_disconnected"));}
   public void onNullBinding(ComponentName name){connected.completeExceptionally(new IOException("handover_export_unavailable"));}
   public void onBindingDied(ComponentName name){connected.completeExceptionally(new IOException("handover_binding_died"));}
  };
  ExecutorService worker=Executors.newSingleThreadExecutor();ScheduledExecutorService timer=Executors.newSingleThreadScheduledExecutor();
  timer.schedule(()->result.completeExceptionally(new IOException("handover_pending_timeout_do_not_replace_enrollment")),30,TimeUnit.SECONDS);
  worker.execute(()->{
   try{
    String binding=HandoverAndroid.binding(context,source);
    main.post(()->{try{bound.set(context.bindService(new Intent().setComponent(new ComponentName(source,source+".HandoverService")),connection,Context.BIND_AUTO_CREATE));if(!bound.get())connected.completeExceptionally(new IOException("handover_export_not_enabled"));}catch(Exception failure){connected.completeExceptionally(new IOException("handover_export_unavailable"));}});
    IBinder binder=connected.get(10,TimeUnit.SECONDS);if(!binding.equals(HandoverAndroid.binding(context,source)))throw new SecurityException("handover_certificate_changed");
    HandoverStore store=new HandoverStore(context);byte[] request=store.prepare(source,binding);byte[] envelope=export(binder,request);store.importEnvelope(request,envelope);
    String digest=HandoverProtocol.sha256(envelope);ack(binder,request,digest);store.acknowledged(request,digest);result.complete(store.inspect());
   }catch(Exception failure){result.completeExceptionally(new IOException("handover_incomplete_retry_same_import"));}
   finally{main.post(()->{if(bound.getAndSet(false))try{context.unbindService(connection);}catch(IllegalArgumentException ignored){}});ACTIVE.set(false);timer.shutdownNow();worker.shutdown();}
  });return result;
 }
 private static byte[] export(IBinder binder,byte[] request)throws Exception{
  Parcel data=Parcel.obtain(),reply=Parcel.obtain();try{data.writeInterfaceToken(HandoverAndroid.INTERFACE);data.writeByteArray(request);if(!binder.transact(HandoverAndroid.EXPORT,data,reply,0))throw new IOException("handover_protocol_unavailable");reply.readException();byte[] envelope=reply.createByteArray();if(envelope==null||envelope.length>HandoverProtocol.MAX_ENVELOPE)throw new IOException("handover_envelope_rejected");reply.enforceNoDataAvail();return envelope;}finally{data.recycle();reply.recycle();}
 }
 private static void ack(IBinder binder,byte[] request,String hash)throws Exception{
  Parcel data=Parcel.obtain(),reply=Parcel.obtain();try{data.writeInterfaceToken(HandoverAndroid.INTERFACE);data.writeByteArray(request);data.writeString(hash);if(!binder.transact(HandoverAndroid.ACK,data,reply,0))throw new IOException("handover_protocol_unavailable");reply.readException();if(reply.readInt()!=1)throw new IOException("handover_ack_rejected");reply.enforceNoDataAvail();}finally{data.recycle();reply.recycle();}
 }
}
