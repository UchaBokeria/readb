package dev.readb.companion;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.util.concurrent.*;
import javax.net.ssl.*;
import com.sun.net.httpserver.*;

public final class OnboardingHttpTest {
 static void check(boolean value,String reason){if(!value)throw new AssertionError(reason);}
 interface Attempt {void run()throws Exception;}
 static void rejects(Attempt attempt,String code)throws Exception{
  try{attempt.run();throw new AssertionError("accepted "+code);}catch(OnboardingHttp.Failure e){check(code.equals(e.code),"wrong code "+e.code);check(!e.toString().contains("TOPSECRET"),"secret diagnostic");}
 }
 public static void main(String[] args)throws Exception{
  check(OnboardingHttp.server(" https://EXAMPLE.org/ ").equals("https://example.org"),"canonical origin");
  check(OnboardingHttp.server("https://example.org:8443").equals("https://example.org:8443"),"explicit port");
  for(String bad:new String[]{"http://example.org","https://user:TOPSECRET@example.org","https://example.org/path","https://example.org/?TOPSECRET=x","https://example.org/#TOPSECRET","https://example.org:0","https://example.org:65536","https://example.org\\evil","https://example.org\n"})
   rejects(()->OnboardingHttp.server(bad),"invalid_server");
  KeyStore keys=KeyStore.getInstance("PKCS12");try(java.io.InputStream in=Files.newInputStream(Path.of(args[0]))){keys.load(in,"test-only".toCharArray());}
  KeyManagerFactory km=KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());km.init(keys,"test-only".toCharArray());
  TrustManagerFactory tm=TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());tm.init(keys);
  SSLContext ssl=SSLContext.getInstance("TLS");ssl.init(km.getKeyManagers(),tm.getTrustManagers(),null);
  SSLSocketFactory original=HttpsURLConnection.getDefaultSSLSocketFactory();
  HttpsServer server=HttpsServer.create(new InetSocketAddress("127.0.0.1",0),0);server.setHttpsConfigurator(new HttpsConfigurator(ssl));
  java.util.concurrent.atomic.AtomicInteger calls=new java.util.concurrent.atomic.AtomicInteger();
  CountDownLatch delayed=new CountDownLatch(1),release=new CountDownLatch(1);
  ExecutorService handlers=Executors.newCachedThreadPool();server.setExecutor(handlers);
  server.createContext("/onboard/v1/claim",e->{
   calls.incrementAndGet();byte[] body=e.getRequestBody().readAllBytes();
   check(e.getRequestMethod().equals("POST"),"method");check(e.getRequestHeaders().getFirst("Content-Type").startsWith("application/json"),"request type");
   String mode=new String(body,StandardCharsets.UTF_8);
   if(mode.equals("delay")){delayed.countDown();try{release.await(5,TimeUnit.SECONDS);}catch(InterruptedException ignored){Thread.currentThread().interrupt();}e.close();return;}
   if(mode.equals("redirect")){e.getResponseHeaders().add("Location","https://elsewhere.invalid/TOPSECRET");e.sendResponseHeaders(302,-1);e.close();return;}
   byte[] out=mode.equals("large")?new byte[32769]:"{\"schema\":1}".getBytes(StandardCharsets.UTF_8);
   e.getResponseHeaders().add("Content-Type",mode.equals("html")?"text/html":"application/json; charset=utf-8");
   if(mode.equals("gzip"))e.getResponseHeaders().add("Content-Encoding","gzip");
   int status=mode.equals("denied")?403:mode.equals("busy")?429:200;
   e.getResponseHeaders().add("Retry-After","7");e.sendResponseHeaders(status,out.length);e.getResponseBody().write(out);e.close();
  });server.start();
  try{
   String base="https://localhost:"+server.getAddress().getPort();
   rejects(()->new OnboardingHttp.Call().post(base,"claim",new byte[0]),"tls_failed");
   HttpsURLConnection.setDefaultSSLSocketFactory(ssl.getSocketFactory());
   rejects(()->new OnboardingHttp.Call().post("https://127.0.0.1:"+server.getAddress().getPort(),"claim",new byte[0]),"tls_failed");
   OnboardingHttp.Response r=new OnboardingHttp.Call().post(base,"claim","ok".getBytes(StandardCharsets.UTF_8));
   check(r.status==200&&new String(r.body,StandardCharsets.UTF_8).equals("{\"schema\":1}"),"actual TLS reply");
   check(new OnboardingHttp.Call().post(base,"claim","denied".getBytes()).status==403,"typed rejection returned for mapping");
   check(new OnboardingHttp.Call().post(base,"claim","busy".getBytes()).retryAfterMillis==7000,"retry delay");
   rejects(()->new OnboardingHttp.Call().post(base,"claim","redirect".getBytes()),"server_redirect");
   rejects(()->new OnboardingHttp.Call().post(base,"claim","large".getBytes()),"invalid_response");
   rejects(()->new OnboardingHttp.Call().post(base,"claim","html".getBytes()),"invalid_response");
   rejects(()->new OnboardingHttp.Call().post(base,"claim","gzip".getBytes()),"invalid_response");
   rejects(()->new OnboardingHttp.Call().post(base,"../TOPSECRET",new byte[0]),"invalid_action");
   OnboardingHttp.Call cancelled=new OnboardingHttp.Call();cancelled.cancel();int before=calls.get();
   rejects(()->cancelled.post(base,"claim",new byte[0]),"cancelled");check(before==calls.get(),"cancel before request");
   rejects(()->new OnboardingHttp.Call().post(base,"claim",new byte[32769]),"invalid_request");
   OnboardingHttp.Call inflight=new OnboardingHttp.Call();
   ExecutorService one=Executors.newSingleThreadExecutor();
   Future<?> running=one.submit(()->{try{rejects(()->inflight.post(base,"claim","delay".getBytes()),"cancelled");}catch(Exception e){throw new RuntimeException(e);}});
   try{check(delayed.await(5,TimeUnit.SECONDS),"request reached actual server");inflight.cancel();release.countDown();running.get(5,TimeUnit.SECONDS);}finally{release.countDown();one.shutdownNow();}
  }finally{release.countDown();server.stop(0);handlers.shutdownNow();HttpsURLConnection.setDefaultSSLSocketFactory(original);}
  System.out.println("HTTPS onboarding transport passed");
 }
}
