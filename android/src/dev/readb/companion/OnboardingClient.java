package dev.readb.companion;

import android.content.Context;
import dev.readb.handover.EnrollmentJournal;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import org.json.JSONObject;

/** One finite native enrollment attempt. Never starts VPN/services or exposes private replies. */
final class OnboardingClient {
 interface Progress {void update(String phase,String message,boolean active);}
 private final EnrollmentStore store;private final Progress progress;
 private volatile boolean cancelled;
 private volatile OnboardingHttp.Call call;
 OnboardingClient(Context context,Progress progress){store=EnrollmentStore.get(context);this.progress=progress;}
 void cancel(){cancelled=true;OnboardingHttp.Call current=call;if(current!=null)current.cancel();}
 private void check()throws IOException{if(cancelled||Thread.currentThread().isInterrupted())throw new IOException("cancelled");}
 private void update(String phase,String message,boolean active){if(!cancelled)progress.update(phase,message,active);}
 private void waitFor(long delay,long deadline)throws Exception{
  long until=Math.min(deadline,System.nanoTime()+delay*1000000L);
  while(System.nanoTime()<until){check();Thread.sleep(Math.min(200,Math.max(1,(until-System.nanoTime())/1000000L)));}check();
 }
 private static String hex(byte[] bytes){StringBuilder out=new StringBuilder();for(byte b:bytes)out.append(String.format(java.util.Locale.ROOT,"%02x",b&255));return out.toString();}
 private static byte[] binary(JSONObject reply,String name,int max)throws Exception{
  if(!reply.has(name))throw new IOException("invalid_response");if(reply.isNull(name))return null;
  Object value=reply.get(name);if(!(value instanceof String)||((String)value).length()>((max+2)/3)*4)throw new IOException("invalid_response");
  byte[] bytes=Base64.getDecoder().decode((String)value);if(bytes.length>max||!Base64.getEncoder().encodeToString(bytes).equals(value))throw new IOException("invalid_response");return bytes;
 }
 private static String blocked(String code){
  if(code.equals("report_firewall_setup_required"))return "The server needs its report firewall configured. Check Add device on the server.";
  if(code.equals("coordinator_maintenance"))return "The server is being updated. Setup will retry shortly.";
  return "Server setup is blocked. Check this device in the server dashboard.";
 }
 void run(String address,String suppliedCode){
  byte[] credential=null,request=null,ack=null;
  try{
   check();String code=suppliedCode==null?null:suppliedCode.replace("-","").trim().toLowerCase(java.util.Locale.ROOT);
   if(code!=null&&!code.matches("[a-f0-9]{16}"))throw new IOException("invalid_code");
   update("preparing","Saving secure setup on this device…",true);
   try(EnrollmentJournal.Session session=code==null?store.session():store.prepare(OnboardingHttp.server(address))){
    credential=session.credential();request=session.request();String hash=hex(MessageDigest.getInstance("SHA-256").digest(request));
    String action=code==null?"resume":"claim";long deadline=System.nanoTime()+120000000000L;int failures=0;
    while(System.nanoTime()<deadline){
     check();JSONObject body=new JSONObject().put("client_auth",hex(credential));
     if(action.equals("claim"))body.put("code",code).put("request_b64",Base64.getEncoder().encodeToString(request));
     else {body.put("request_sha256",hash);if(action.equals("ack"))body.put("ack_b64",Base64.getEncoder().encodeToString(ack));}
     byte[] payload=body.toString().getBytes(StandardCharsets.UTF_8);OnboardingHttp.Response response;
     try{call=new OnboardingHttp.Call();check();response=call.post(session.url(),action,payload);}
     catch(OnboardingHttp.Failure e){
      check();if(e.code.equals("tls_failed")||e.code.equals("invalid_server")||e.code.equals("server_redirect")||e.code.equals("invalid_response"))throw e;
      failures=Math.min(4,failures+1);update("retrying","Cannot reach the server. Retrying; you can cancel safely.",true);waitFor(1000L<<failures,deadline);continue;
     }finally{Arrays.fill(payload,(byte)0);call=null;}
     try{
      JSONObject reply=new JSONObject(new String(response.body,StandardCharsets.UTF_8));
      if(!(reply.get("schema") instanceof Number)||reply.getInt("schema")!=1)throw new IOException("invalid_response");
      String result=reply.getString("code");
      if(response.status==403)throw new IOException("invalid_setup");
      if(response.status==429||response.status==503){
       if(!(result.equals("setup_rate_limited")||result.equals("setup_blocked")))throw new IOException("invalid_response");
       update("blocked",response.status==429?"Too many attempts. Waiting before retrying.":blocked(reply.optString("blocker","")),true);
       waitFor(Math.max(1000,Math.min(60000,Math.max(response.retryAfterMillis,reply.optLong("retry_after_ms",1000)))),deadline);continue;
      }
      if(response.status!=200||!hash.equals(reply.getString("request_sha256")))throw new IOException("invalid_response");
      if(!result.equals("setup_pending")&&!result.equals("setup_envelope")&&!result.equals("setup_complete"))throw new IOException("invalid_response");
      byte[] context=binary(reply,"context_b64",116),envelope=binary(reply,"envelope_b64",12288),receipt=binary(reply,"final_b64",132);
      if(context!=null)store.bind(context);
      if(envelope!=null){if(context==null)throw new IOException("invalid_response");if(ack!=null)Arrays.fill(ack,(byte)0);ack=store.accept(context,request,envelope);}
      if(receipt!=null){if(context==null||!result.equals("setup_complete"))throw new IOException("invalid_response");store.finish(context,request,receipt);if(!store.ready())throw new IOException("storage_failed");update("complete","Device setup saved securely. Allow readb VPN, then start the private link.",false);return;}
      if(result.equals("setup_complete")||(result.equals("setup_envelope")&&ack==null))throw new IOException("invalid_response");
      failures=0;action=ack==null?"resume":"ack";update("preparing",ack==null?"Server is preparing this device…":"Setup saved. Waiting for server confirmation…",true);
      waitFor(Math.max(250,Math.min(15000,reply.optLong("retry_after_ms",1000))),deadline);
     }finally{Arrays.fill(response.body,(byte)0);}
    }
    update("paused","Setup is taking longer than expected. Choose Resume setup to continue safely.",false);
   }
  }catch(Exception failure){
   if(cancelled||Thread.currentThread().isInterrupted())return;
   String reason=failure.getMessage(),message;
   if("invalid_code".equals(reason))message="Enter the 16-character setup code from Add device on your server.";
   else if("invalid_setup".equals(reason))message="The code or setup session is not valid. Check the code or create another on your server.";
   else if("invalid_server".equals(reason))message="Enter an HTTPS server address, without a path, password or query.";
   else if("tls_failed".equals(reason))message="The server certificate could not be verified. Check its HTTPS address and certificate.";
   else if("server_redirect".equals(reason))message="The server redirected setup. Use its final HTTPS address.";
   else if("invalid_response".equals(reason))message="The server returned an incompatible setup reply. Check its readb version.";
   else message="Setup could not finish. Saved data was kept. Resume or check the server before trying again.";
   update("paused",message,false);
  }finally{if(credential!=null)Arrays.fill(credential,(byte)0);if(request!=null)Arrays.fill(request,(byte)0);if(ack!=null)Arrays.fill(ack,(byte)0);call=null;}
 }
}
