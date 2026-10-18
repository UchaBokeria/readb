package dev.readb.companion;
import android.app.Instrumentation;
import android.os.Bundle;
import dev.readb.handover.*;
import java.util.Arrays;
import org.json.JSONObject;

/** Synthetic isolated namespace only. Never binds an exporter or starts a service. */
public final class HandoverChecks extends Instrumentation {
 @Override public void onCreate(Bundle args){super.onCreate(args);start();}
 private void check(boolean value){if(!value)throw new AssertionError("handover_check_failed");}
 @Override public void onStart(){Bundle result=new Bundle();HandoverStore store=null,quest=null;
  try{
   String storePrefix="readb-handover-test-"+java.util.UUID.randomUUID().toString();store=new HandoverStore(getTargetContext(),storePrefix);
   String binding=HandoverAndroid.PIXEL+"\n"+HandoverAndroid.RECIPIENT+"\n"+"a".repeat(64)+"\n"+"b".repeat(64);
   byte[] request=store.prepare(HandoverAndroid.PIXEL,binding);check(Arrays.equals(request,store.prepare(HandoverAndroid.PIXEL,binding)));
   byte[] synthetic=new JSONObject().put("schema",1).put("source_package",HandoverAndroid.PIXEL).put("report_enabled",false).put("report_token","synthetic-not-a-live-token".repeat(2)).toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
   byte[] envelope=HandoverProtocol.seal(request,synthetic,binding);store.importEnvelope(request,envelope);
   check("imported".equals(store.inspect().getString("phase")));check(!store.inspect().optBoolean("report_enabled",true));
   store=new HandoverStore(getTargetContext(),storePrefix);store.importEnvelope(request,envelope);store.acknowledged(request,HandoverProtocol.sha256(envelope));check("complete".equals(store.inspect().getString("phase")));
   byte[] corrupted=envelope.clone();corrupted[corrupted.length-1]^=1;boolean rejected=false;try{store.importEnvelope(request,corrupted);}catch(Exception expected){rejected=true;}check(rejected);
   check(!new String(store.ciphertextForTest(),java.nio.charset.StandardCharsets.ISO_8859_1).contains("synthetic-not-a-live-token".repeat(2)));
   quest=new HandoverStore(getTargetContext(),"readb-handover-test-"+java.util.UUID.randomUUID().toString());
   String questBinding=HandoverAndroid.QUEST+"\n"+HandoverAndroid.RECIPIENT+"\n"+"a".repeat(64)+"\n"+"b".repeat(64);
   byte[] qr=quest.prepare(HandoverAndroid.QUEST,questBinding);
   JSONObject consent=new JSONObject().put("enabled",false).put("wake_on_connect",false).put("ssid_sha256","c".repeat(64)).put("bssid_sha256","d".repeat(64));
   JSONObject qp=new JSONObject().put("schema",1).put("source_package",HandoverAndroid.QUEST).put("report_enabled",false).put("report_token","synthetic-not-a-live-token".repeat(2)).put("vpn_config","").put("vpn_enabled",false).put("pin_present",true).put("pin_enabled",false).put("pin","0000").put("consent",consent);
   quest.importEnvelope(qr,HandoverProtocol.seal(qr,qp.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8),questBinding));
   check(quest.inspect().getBoolean("pin_present")&&!quest.inspect().getBoolean("pin_enabled")&&!quest.inspect().getBoolean("recovery_activated"));
   check(quest.payloadForTest().getJSONObject("consent").toString().equals(consent.toString()));
   boolean callerRejected=false;try{HandoverAndroid.authorizeRecipient(getTargetContext(),HandoverAndroid.QUEST,android.os.Process.myUid());}catch(Exception expected){callerRejected=true;}check(callerRejected);
   result.putString("result","handover_checks_passed");result.putInt("checks",9);
  }catch(Throwable failed){result.putString("result","handover_checks_failed");}
  finally{if(quest!=null)try{quest.clearFixture();}catch(Exception failed){result.putString("result","handover_fixture_cleanup_failed");}if(store!=null)try{store.clearFixture();}catch(Exception failed){result.putString("result","handover_fixture_cleanup_failed");}}
  finish("handover_checks_passed".equals(result.getString("result"))?-1:0,result);
 }
}
