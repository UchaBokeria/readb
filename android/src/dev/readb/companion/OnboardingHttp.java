package dev.readb.companion;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.concurrent.*;
import javax.net.ssl.*;

/** Native-only verified HTTPS. Carries private bodies; never log requests or replies. */
final class OnboardingHttp {
 private static final int LIMIT=32768;
 private static final ScheduledExecutorService DEADLINES=Executors.newSingleThreadScheduledExecutor(r->{Thread t=new Thread(r,"readb-setup-deadline");t.setDaemon(true);return t;});
 private OnboardingHttp(){}
 static final class Failure extends IOException {
  final String code;
  Failure(String code){super(code);this.code=code;}
 }
 static String server(String text)throws Failure{
  try{
   if(text==null||text.length()>2048||text.chars().anyMatch(Character::isISOControl))throw new Exception();
   URI uri=new URI(text.trim());String host=uri.getHost();int port=uri.getPort();
   if(!"https".equalsIgnoreCase(uri.getScheme())||host==null||host.isEmpty()||uri.getRawUserInfo()!=null||uri.getRawQuery()!=null||uri.getRawFragment()!=null||!(uri.getRawPath().isEmpty()||uri.getRawPath().equals("/"))||port==0||port>65535||port< -1)throw new Exception();
   return new URI("https",null,host.toLowerCase(Locale.ROOT),port==443?-1:port,null,null,null).toASCIIString();
  }catch(Exception invalid){throw new Failure("invalid_server");}
 }
 static final class Response {
  final int status;final byte[] body;final long retryAfterMillis;
  Response(int status,byte[] body,long retry){this.status=status;this.body=body;retryAfterMillis=retry;}
  @Override public String toString(){return "[private setup response]";}
 }
 static final class Call {
  private boolean cancelled,started,timedOut;
  private HttpsURLConnection connection;
  synchronized void cancel(){cancelled=true;if(connection!=null)connection.disconnect();}
  private synchronized void expire(){timedOut=true;if(connection!=null)connection.disconnect();}
  private synchronized void check()throws Failure{if(cancelled)throw new Failure("cancelled");if(timedOut)throw new Failure("server_timeout");}
  Response post(String address,String action,byte[] body)throws Failure{
   String origin=server(address);
   if(!action.equals("claim")&&!action.equals("resume")&&!action.equals("ack"))throw new Failure("invalid_action");
   if(body==null||body.length>LIMIT)throw new Failure("invalid_request");
   ScheduledFuture<?> deadline=null;HttpsURLConnection c=null;
   try{
    synchronized(this){check();if(started)throw new Failure("request_already_used");started=true;c=(HttpsURLConnection)new URL(origin+"/onboard/v1/"+action).openConnection();connection=c;}
    // Default platform trust and hostname verification are intentional. No TLS overrides.
    c.setInstanceFollowRedirects(false);c.setConnectTimeout(10000);c.setReadTimeout(10000);c.setUseCaches(false);
    c.setRequestMethod("POST");c.setDoOutput(true);c.setRequestProperty("Content-Type","application/json; charset=utf-8");c.setRequestProperty("Accept","application/json");c.setRequestProperty("Accept-Encoding","identity");c.setFixedLengthStreamingMode(body.length);
    deadline=DEADLINES.schedule(this::expire,30,TimeUnit.SECONDS);
    check();try(OutputStream out=c.getOutputStream()){out.write(body);}check();
    int status=c.getResponseCode();check();
    if(status>=300&&status<400)throw new Failure("server_redirect");
    if(status!=200&&status!=400&&status!=403&&status!=404&&status!=429&&status!=503)throw new Failure("server_unavailable");
    String type=c.getContentType(),encoding=c.getContentEncoding();
    if(type==null||!type.split(";",2)[0].trim().equalsIgnoreCase("application/json")||(encoding!=null&&!encoding.equalsIgnoreCase("identity"))||c.getContentLengthLong()>LIMIT)throw new Failure("invalid_response");
    byte[] bytes;
    try(InputStream in=status>=400?c.getErrorStream():c.getInputStream()){
     if(in==null)throw new Failure("invalid_response");
     ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] buffer=new byte[2048];int count;
     while((count=in.read(buffer))!=-1){check();if(out.size()+count>LIMIT)throw new Failure("invalid_response");out.write(buffer,0,count);}
     bytes=out.toByteArray();
    }
    check();long retry=0;String raw=c.getHeaderField("Retry-After");
    if(raw!=null&&raw.matches("[0-9]{1,5}"))retry=Math.min(60000,Long.parseLong(raw)*1000);
    return new Response(status,bytes,retry);
   }catch(Failure e){throw e;}
   catch(Exception e){check();if(e instanceof SSLException)throw new Failure("tls_failed");if(e instanceof java.net.SocketTimeoutException)throw new Failure("server_timeout");throw new Failure("server_unreachable");}
   finally{if(deadline!=null)deadline.cancel(false);synchronized(this){connection=null;}if(c!=null)c.disconnect();}
  }
 }
}
