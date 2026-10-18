package dev.readb.companion;

import android.content.Context;
import android.security.keystore.*;
import android.util.Base64;
import dev.readb.handover.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import org.json.JSONObject;

/** Separate encrypted rollback/recovery material. Import never activates a VPN, PIN or consent. */
final class HandoverStore {
 private final Context context;private final String prefix;private final HandoverJournal.Storage disk;
 HandoverStore(Context context){this(context,"readb-handover");}
 HandoverStore(Context context,String prefix){
  if(!prefix.equals("readb-handover")&&!prefix.matches("readb-handover-test-[a-f0-9-]{36}"))throw new IllegalArgumentException("handover_namespace_rejected");
  this.context=context.getApplicationContext();this.prefix=prefix;this.disk=HandoverAndroid.storage(context,prefix+".enc");
 }
 private KeyStore keys()throws Exception{KeyStore k=KeyStore.getInstance("AndroidKeyStore");k.load(null);return k;}
 private String rsaAlias(){return prefix+".recipient.v1";}
 private String aesAlias(){return prefix+".store.v1";}
 private javax.crypto.SecretKey aes(boolean create)throws Exception{
  KeyStore k=keys();if(!k.containsAlias(aesAlias())){
   if(!create)throw new IOException("handover_store_key_missing");KeyGenerator g=KeyGenerator.getInstance("AES","AndroidKeyStore");
   g.init(new KeyGenParameterSpec.Builder(aesAlias(),KeyProperties.PURPOSE_ENCRYPT|KeyProperties.PURPOSE_DECRYPT).setKeySize(256).setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).setUserAuthenticationRequired(false).setUnlockedDeviceRequired(false).build());g.generateKey();
  }return(javax.crypto.SecretKey)keys().getKey(aesAlias(),null);
 }
 private byte[] aad(){return("readb-handover-store-v1:"+prefix).getBytes(StandardCharsets.UTF_8);}
 private JSONObject load()throws Exception{
  byte[] bytes=disk.readConfirmed();if(bytes==null)return null;if(bytes.length<30||bytes[0]!=1)throw new IOException("handover_store_rejected");
  Cipher c=Cipher.getInstance("AES/GCM/NoPadding");c.init(Cipher.DECRYPT_MODE,aes(false),new GCMParameterSpec(128,bytes,1,12));c.updateAAD(aad());byte[] plaintext=c.doFinal(bytes,13,bytes.length-13);
  try{JSONObject state=new JSONObject(new String(plaintext,StandardCharsets.UTF_8));
   if(state.getInt("schema")!=1||!HandoverAndroid.source(state.getString("source"))||!Arrays.asList("pending","imported","complete").contains(state.getString("phase")))throw new IOException("handover_store_schema_rejected");return state;
  }finally{Arrays.fill(plaintext,(byte)0);}
 }
 private void save(JSONObject state)throws Exception{
  byte[] plaintext=state.toString().getBytes(StandardCharsets.UTF_8);if(plaintext.length>150000)throw new IOException("handover_store_too_large");
  try{Cipher c=Cipher.getInstance("AES/GCM/NoPadding");c.init(Cipher.ENCRYPT_MODE,aes(true));c.updateAAD(aad());ByteArrayOutputStream out=new ByteArrayOutputStream();out.write(1);out.write(c.getIV());out.write(c.doFinal(plaintext));disk.write(out.toByteArray());}
  finally{Arrays.fill(plaintext,(byte)0);}
 }
 synchronized byte[] prepare(String source,String binding)throws Exception{
  if(!HandoverAndroid.source(source)||binding==null||!binding.startsWith(source+"\n"+HandoverAndroid.RECIPIENT+"\n"))throw new IOException("handover_source_rejected");
  JSONObject state=load();if(state!=null){if(!source.equals(state.getString("source"))||!binding.equals(state.getString("binding")))throw new IOException("handover_other_import_pending");return Base64.decode(state.getString("request"),Base64.NO_WRAP);}
  if(prefix.equals("readb-handover")&&ProfileStore.exists(context))throw new IOException("handover_existing_enrollment_preserved");
  if(!context.getSystemService(android.os.UserManager.class).isUserUnlocked())throw new IOException("handover_unlock_required");
  KeyStore k=keys();if(!k.containsAlias(rsaAlias())){
   KeyPairGenerator g=KeyPairGenerator.getInstance("RSA","AndroidKeyStore");g.initialize(new KeyGenParameterSpec.Builder(rsaAlias(),KeyProperties.PURPOSE_DECRYPT).setKeySize(3072).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP).setDigests(KeyProperties.DIGEST_SHA256,KeyProperties.DIGEST_SHA1).setUserAuthenticationRequired(false).build());g.generateKeyPair();
  }
  byte[] request=HandoverProtocol.request(HandoverProtocol.random(32),keys().getCertificate(rsaAlias()).getPublicKey().getEncoded());
  save(new JSONObject().put("schema",1).put("source",source).put("binding",binding).put("request",Base64.encodeToString(request,Base64.NO_WRAP)).put("phase","pending"));return request;
 }
 private JSONObject require(byte[] request)throws Exception{
  JSONObject state=load();if(state==null||!MessageDigest.isEqual(request,Base64.decode(state.getString("request"),Base64.NO_WRAP)))throw new IOException("handover_request_mismatch");return state;
 }
 private static void fields(JSONObject object,String... allowed)throws Exception{
  Set<String> keys=new HashSet<>(Arrays.asList(allowed));Iterator<String> i=object.keys();while(i.hasNext())if(!keys.contains(i.next()))throw new IOException("handover_unknown_field");
 }
 private static void validatePayload(JSONObject payload,String source)throws Exception{
  if(payload.getInt("schema")!=1||!source.equals(payload.getString("source_package")))throw new IOException("handover_payload_source_mismatch");
  payload.getBoolean("report_enabled");String token=payload.getString("report_token");if(token.length()<40||token.length()>256)throw new IOException("handover_report_credential_rejected");
  if(HandoverAndroid.PIXEL.equals(source)){fields(payload,"schema","source_package","report_enabled","report_token");return;}
  fields(payload,"schema","source_package","report_enabled","report_token","vpn_config","vpn_enabled","pin_present","pin_enabled","pin","consent");
  if(payload.getString("vpn_config").length()>8192)throw new IOException("handover_vpn_too_large");payload.getBoolean("vpn_enabled");
  boolean present=payload.getBoolean("pin_present"),enabled=payload.getBoolean("pin_enabled");String pin=payload.optString("pin","");
  if((present&&!pin.matches("[0-9]{4,12}"))||(!present&&!pin.isEmpty())||(enabled&&!present))throw new IOException("handover_pin_rejected");
  JSONObject consent=payload.getJSONObject("consent");fields(consent,"enabled","wake_on_connect","ssid_sha256","bssid_sha256");
  boolean consentEnabled=consent.getBoolean("enabled");consent.getBoolean("wake_on_connect");
  for(String key:new String[]{"ssid_sha256","bssid_sha256"}){String hash=consent.getString(key);if(!hash.matches("[a-f0-9]{64}")&&(!hash.isEmpty()||consentEnabled))throw new IOException("handover_consent_rejected");}
 }
 synchronized void importEnvelope(byte[] request,byte[] envelope)throws Exception{
  JSONObject state=require(request);String hash=HandoverProtocol.sha256(envelope);
  if(!state.getString("phase").equals("pending")){if(!hash.equals(state.getString("envelope_sha256")))throw new IOException("handover_receipt_conflict");save(state);return;}
  byte[] plaintext=HandoverProtocol.open(request,envelope,(PrivateKey)keys().getKey(rsaAlias(),null),state.getString("binding"));
  try{JSONObject payload=new JSONObject(new String(plaintext,StandardCharsets.UTF_8));validatePayload(payload,state.getString("source"));save(state.put("payload",payload).put("phase","imported").put("envelope_sha256",hash));}
  finally{Arrays.fill(plaintext,(byte)0);}
 }
 synchronized void acknowledged(byte[] request,String hash)throws Exception{
  JSONObject state=require(request);if(state.getString("phase").equals("pending")||!hash.equals(state.getString("envelope_sha256")))throw new IOException("handover_ack_rejected");save(state.put("phase","complete"));
 }
 synchronized JSONObject inspect()throws Exception{
  JSONObject s=load();if(s==null)return new JSONObject().put("phase","none");JSONObject result=new JSONObject().put("phase",s.getString("phase")).put("source",s.getString("source"));
  if(s.has("payload")){JSONObject p=s.getJSONObject("payload");result.put("report_enabled",p.getBoolean("report_enabled")).put("pin_present",p.optBoolean("pin_present",false)).put("pin_enabled",p.optBoolean("pin_enabled",false)).put("recovery_activated",false);}
  return result;
 }
 JSONObject payloadForTest()throws Exception{if(!prefix.startsWith("readb-handover-test-"))throw new SecurityException();return load().getJSONObject("payload");}
 byte[] ciphertextForTest()throws Exception{if(!prefix.startsWith("readb-handover-test-"))throw new SecurityException();return disk.readConfirmed();}
 void clearFixture()throws Exception{
  if(!prefix.startsWith("readb-handover-test-"))throw new SecurityException();File dir=context.createDeviceProtectedStorageContext().getFilesDir();
  for(String suffix:new String[]{".enc",".enc.bak",".enc.new"})java.nio.file.Files.deleteIfExists(new File(dir,prefix+suffix).toPath());
  KeyStore k=keys();for(String alias:new String[]{rsaAlias(),aesAlias()})if(k.containsAlias(alias))k.deleteEntry(alias);
 }
}
