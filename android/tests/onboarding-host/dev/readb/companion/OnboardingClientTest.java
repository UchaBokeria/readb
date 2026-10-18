package dev.readb.companion;

import android.content.Context;
import dev.readb.handover.EnrollmentJournal;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import javax.net.ssl.*;
import com.sun.net.httpserver.*;
import org.json.JSONObject;

/** Actual production client/HTTP/journal/codec; only Android storage is a host facade. */
public final class OnboardingClientTest {
 static AtomicInteger checks=new AtomicInteger();static Path dir;static byte[] context,request,envelope,ack,receipt;static String hash;static volatile String base,mode,auth;
 static AtomicInteger claims=new AtomicInteger(),resumes=new AtomicInteger(),acks=new AtomicInteger();
 static AtomicReference<Throwable> serverFailure=new AtomicReference<>();
 static CountDownLatch reached,release;
 static void check(boolean ok,String why){if(!ok)throw new AssertionError(why);checks.incrementAndGet();}
 static String b64(byte[] b){return Base64.getEncoder().encodeToString(b);}
 static String hex(byte[] b){StringBuilder s=new StringBuilder();for(byte v:b)s.append(String.format(Locale.ROOT,"%02x",v&255));return s.toString();}
 static JSONObject reply(boolean complete)throws Exception{
  return new JSONObject().put("schema",1).put("code",complete?"setup_complete":"setup_envelope").put("phase",complete?"complete":"envelope_committed").put("request_sha256",hash).put("context_b64",b64(context)).put("envelope_b64",complete?JSONObject.NULL:b64(envelope)).put("final_b64",complete?b64(receipt):JSONObject.NULL).put("retry_after_ms",0).put("message","TOPSECRET server text must never reach UI");
 }
 static void serve(HttpExchange e){
  try{
   String action=e.getRequestURI().getPath().substring("/onboard/v1/".length());JSONObject body=new JSONObject(new String(e.getRequestBody().readAllBytes(),StandardCharsets.UTF_8));
   EnrollmentStore store=EnrollmentStore.fixture;
   check(store.disk.bytes!=null,"network occurred before durable bootstrap");
   try(EnrollmentJournal.Session session=store.session()){
    String actual=hex(session.credential());check(actual.equals(body.getString("client_auth")),"wrong persisted resume credential");
    if(auth==null)auth=actual;check(auth.equals(actual),"credential changed within attempt");
   }
   JSONObject response;
   if(action.equals("claim")){
    claims.incrementAndGet();check(body.getString("code").equals("abcd1234ef567890"),"code normalization");check(Arrays.equals(Base64.getDecoder().decode(body.getString("request_b64")),request),"recipient request changed");
    if(mode.equals("cancel")){reached.countDown();release.await(5,TimeUnit.SECONDS);}
    response=reply(false);
    if(mode.equals("wrong_hash"))response.put("request_sha256","0".repeat(64));
    if(mode.equals("missing_context"))response.put("context_b64",JSONObject.NULL);
    if(mode.equals("noncanonical"))response.put("context_b64",b64(context).replace("=",""));
    if(mode.equals("fractional_schema"))response.put("schema",1.5);
    if(mode.equals("invalid_base64"))response.put("context_b64","%%%TOPSECRET%%%");
    if(mode.equals("no_space"))store.disk.failWriteAt=3;
   }else if(action.equals("resume")){
    resumes.incrementAndGet();check(hash.equals(body.getString("request_sha256")),"wrong resume hash");response=reply(false);
   }else if(action.equals("ack")){
    int count=acks.incrementAndGet();check(hash.equals(body.getString("request_sha256")),"wrong ACK request");check(Arrays.equals(Base64.getDecoder().decode(body.getString("ack_b64")),ack),"ACK changed on retry");
    check(!store.ready(),"client ready before final receipt was returned");
    // A real server has finalized here; dropping its reply must replay this final.
    if(mode.equals("dropped_ack")&&count==1){e.close();return;}
    response=reply(true);if(mode.equals("wrong_final"))response.put("final_b64",b64(ack));
   }else throw new AssertionError("unexpected action");
   byte[] bytes=(mode.equals("malformed_json")?"{":response.toString()).getBytes(StandardCharsets.UTF_8);e.getResponseHeaders().set("Content-Type","application/json");e.sendResponseHeaders(200,bytes.length);e.getResponseBody().write(bytes);e.close();
  }catch(Throwable failure){serverFailure.compareAndSet(null,failure);try{byte[] bad="{}".getBytes(StandardCharsets.UTF_8);e.getResponseHeaders().set("Content-Type","application/json");e.sendResponseHeaders(400,bad.length);e.getResponseBody().write(bad);}catch(Exception ignored){}e.close();}
 }
 static List<String> run(String scenario,boolean existing)throws Exception{
  mode=scenario;auth=null;claims.set(0);resumes.set(0);acks.set(0);serverFailure.set(null);
  EnrollmentStore.fixture=new EnrollmentStore(dir);EnrollmentStore store=EnrollmentStore.fixture;
  if(existing){try(EnrollmentJournal.Session s=store.prepare(base)){auth=hex(s.credential());}store.bind(context);check(Arrays.equals(store.accept(context,request,envelope),ack),"fixture saved ACK");}
  List<String> progress=new CopyOnWriteArrayList<>();
  new OnboardingClient(new Context(),(phase,message,active)->progress.add(phase+":"+message+":"+active)).run(existing?null:base,existing?null:"ABCD-1234-EF56-7890");
  if(serverFailure.get()!=null)throw new AssertionError("server protocol check",serverFailure.get());
  for(String text:progress)check(!text.contains("TOPSECRET")&&!text.contains(auth==null?"not-a-credential":auth),"private server/credential echoed");
  return progress;
 }
 static String last(List<String> messages){return messages.get(messages.size()-1);}
 public static void main(String[] args)throws Exception{
  dir=Path.of(args[0]);context=Files.readAllBytes(dir.resolve("context"));request=Files.readAllBytes(dir.resolve("request"));envelope=Files.readAllBytes(dir.resolve("envelope"));ack=Files.readAllBytes(dir.resolve("ack"));receipt=Files.readAllBytes(dir.resolve("final"));hash=hex(MessageDigest.getInstance("SHA-256").digest(request));
  KeyStore keys=KeyStore.getInstance("PKCS12");try(java.io.InputStream in=Files.newInputStream(dir.resolve("local.p12"))){keys.load(in,"test-only".toCharArray());}
  KeyManagerFactory km=KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());km.init(keys,"test-only".toCharArray());TrustManagerFactory tm=TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());tm.init(keys);
  SSLContext ssl=SSLContext.getInstance("TLS");ssl.init(km.getKeyManagers(),tm.getTrustManagers(),null);SSLSocketFactory original=HttpsURLConnection.getDefaultSSLSocketFactory();
  HttpsServer server=HttpsServer.create(new InetSocketAddress("127.0.0.1",0),0);server.setHttpsConfigurator(new HttpsConfigurator(ssl));ExecutorService handlers=Executors.newCachedThreadPool();server.setExecutor(handlers);server.createContext("/onboard/v1/",OnboardingClientTest::serve);server.start();base="https://localhost:"+server.getAddress().getPort();
  try{
   // Test process only: trust its synthetic localhost cert. Production stays unchanged.
   HttpsURLConnection.setDefaultSSLSocketFactory(ssl.getSocketFactory());
   check(last(run("happy",false)).startsWith("complete:"),"normal setup did not complete");check(EnrollmentStore.fixture.ready(),"final not durably ready");check(claims.get()==1&&acks.get()==1,"wrong normal action order");
   check(last(run("dropped_ack",false)).startsWith("complete:"),"lost final reply did not recover");check(acks.get()==2,"lost ACK/final reply was not replayed");
   check(last(run("restart",true)).startsWith("complete:"),"saved Android ACK did not resume");check(claims.get()==0&&resumes.get()==1&&acks.get()==1,"restart reclaimed code instead of session");
   for(String scenario:new String[]{"wrong_hash","missing_context","noncanonical","fractional_schema","no_space","wrong_final","invalid_base64","malformed_json"}){
    List<String> messages=run(scenario,false);check(last(messages).startsWith("paused:"),scenario+" was not refused");check(!EnrollmentStore.fixture.ready(),scenario+" activated profile");
    if(!scenario.equals("wrong_final"))check(acks.get()==0,scenario+" emitted ACK before validated durable save");
    if(scenario.equals("malformed_json")||scenario.equals("invalid_base64"))check(last(messages).contains("incompatible setup reply"),scenario+" did not identify incompatible server reply");
   }
   mode="cancel";auth=null;serverFailure.set(null);claims.set(0);resumes.set(0);acks.set(0);EnrollmentStore.fixture=new EnrollmentStore(dir);reached=new CountDownLatch(1);release=new CountDownLatch(1);List<String> cancelled=new CopyOnWriteArrayList<>();OnboardingClient client=new OnboardingClient(new Context(),(p,m,a)->cancelled.add(p));
   ExecutorService worker=Executors.newSingleThreadExecutor();try{Future<?> task=worker.submit(()->client.run(base,"abcd1234ef567890"));check(reached.await(5,TimeUnit.SECONDS),"cancel request did not reach TLS server");client.cancel();int before=cancelled.size();release.countDown();task.get(5,TimeUnit.SECONDS);check(cancelled.size()==before,"cancelled callback updated UI");check(acks.get()==0&&!EnrollmentStore.fixture.ready(),"cancelled attempt ACKed or activated");}finally{release.countDown();worker.shutdownNow();}
   mode="happy";List<String> resumed=new CopyOnWriteArrayList<>();new OnboardingClient(new Context(),(p,m,a)->resumed.add(p)).run(null,null);check(resumed.contains("complete"),"cancelled bootstrap could not resume");
   EnrollmentStore.fixture=new EnrollmentStore(dir);OnboardingClient early=new OnboardingClient(new Context(),(p,m,a)->{throw new AssertionError("cancel-before-run callback");});early.cancel();early.run(base,"abcd1234ef567890");check(EnrollmentStore.fixture.disk.bytes==null,"cancel-before-run created state");
  }finally{if(release!=null)release.countDown();server.stop(0);handlers.shutdownNow();HttpsURLConnection.setDefaultSSLSocketFactory(original);}
  System.out.println("Native onboarding protocol checks="+checks.get());
 }
}
