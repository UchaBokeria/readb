package dev.readb.companion;

import android.content.Context;
import android.security.keystore.*;
import android.system.*;
import android.util.AtomicFile;
import dev.readb.handover.EnrollmentDelivery;
import dev.readb.handover.EnrollmentJournal;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import org.json.JSONObject;

/** Native-only enrollment storage. No transport, UI, permission or service effects. */
final class EnrollmentStore {
 private static final String PREFIX="readb-enrollment-delivery";
 private static EnrollmentStore production;
 private final Context context;private final String prefix;private final AtomicFile file;private final File dir;
 private final EnrollmentJournal journal;
 private EnrollmentStore(Context c,String prefix){
  if(!prefix.equals(PREFIX)&&!prefix.matches("readb-enrollment-test-[a-f0-9-]{36}"))throw new IllegalArgumentException("enrollment_namespace_rejected");
  this.context=c.getApplicationContext();this.prefix=prefix;dir=c.createDeviceProtectedStorageContext().getFilesDir();file=new AtomicFile(new File(dir,prefix+".enc"));
  journal=new EnrollmentJournal(new EnrollmentJournal.Storage(){
   public byte[] readConfirmed()throws Exception{byte[] bytes=readCiphertext();if(bytes==null)return null;byte[] plain=null;
    try{if(bytes.length<30||bytes[0]!=1)throw rejected();Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.DECRYPT_MODE,aes(false),new GCMParameterSpec(128,bytes,1,12));cipher.updateAAD(aad());plain=cipher.doFinal(bytes,13,bytes.length-13);return plain;}
    catch(Exception failure){if(plain!=null)Arrays.fill(plain,(byte)0);throw rejected();}
   }
   public void write(byte[] plain)throws Exception{
    Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.ENCRYPT_MODE,aes(true));cipher.updateAAD(aad());ByteArrayOutputStream out=new ByteArrayOutputStream();out.write(1);out.write(cipher.getIV());out.write(cipher.doFinal(plain));writeCiphertext(out.toByteArray());
   }
  },new EnrollmentJournal.Recipient(){
   public byte[] request()throws Exception{
    KeyStore keys=keys();if(!keys.containsAlias(rsaAlias())){KeyPairGenerator g=KeyPairGenerator.getInstance("RSA","AndroidKeyStore");g.initialize(new KeyGenParameterSpec.Builder(rsaAlias(),KeyProperties.PURPOSE_DECRYPT).setKeySize(3072).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP).setDigests(KeyProperties.DIGEST_SHA256,KeyProperties.DIGEST_SHA1).setUserAuthenticationRequired(false).setUnlockedDeviceRequired(false).build());g.generateKeyPair();}
    byte[] installation=new byte[32],nonce=new byte[32];SecureRandom random=new SecureRandom();random.nextBytes(installation);random.nextBytes(nonce);return EnrollmentDelivery.request(installation,nonce,keys().getCertificate(rsaAlias()).getPublicKey().getEncoded());
   }
   public PrivateKey key()throws Exception{PrivateKey key=(PrivateKey)keys().getKey(rsaAlias(),null);if(key==null)throw rejected();return key;}
  },(binding,profile)->{
   try{JSONObject p=ProfileStore.validateBytes(profile);DataInputStream in=new DataInputStream(new ByteArrayInputStream(binding));if(in.skipBytes(64)!=64)throw rejected();int n=in.readInt();byte[] id=new byte[n];in.readFully(id);if(!p.getString("device_id").equals(new String(id,StandardCharsets.US_ASCII)))throw rejected();}catch(Exception invalid){throw rejected();}
  });
 }
 private static IOException rejected(){return new IOException("enrollment_store_unavailable");}
 static EnrollmentStore get(Context c){synchronized(ProfileStore.class){if(production==null)production=new EnrollmentStore(c,PREFIX);return production;}}
 static boolean present(Context c){File base=new File(c.createDeviceProtectedStorageContext().getFilesDir(),PREFIX+".enc");return base.exists()||new File(base+".bak").exists()||new File(base+".new").exists();}
 private KeyStore keys()throws Exception{KeyStore k=KeyStore.getInstance("AndroidKeyStore");k.load(null);return k;}
 private String rsaAlias(){return prefix+".recipient.v1";}private String aesAlias(){return prefix+".store.v1";}
 private byte[] aad(){return ("readb-enrollment-storage-v1:"+prefix).getBytes(StandardCharsets.UTF_8);}
 private javax.crypto.SecretKey aes(boolean create)throws Exception{
  KeyStore k=keys();if(!k.containsAlias(aesAlias())){if(!create)throw rejected();KeyGenerator g=KeyGenerator.getInstance("AES","AndroidKeyStore");g.init(new KeyGenParameterSpec.Builder(aesAlias(),KeyProperties.PURPOSE_ENCRYPT|KeyProperties.PURPOSE_DECRYPT).setKeySize(256).setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).setUserAuthenticationRequired(false).setUnlockedDeviceRequired(false).build());g.generateKey();}return(javax.crypto.SecretKey)keys().getKey(aesAlias(),null);
 }
 private void syncDirectory()throws Exception{FileDescriptor fd=Os.open(dir.getAbsolutePath(),OsConstants.O_RDONLY|OsConstants.O_CLOEXEC,0);try{if(!OsConstants.S_ISDIR(Os.fstat(fd).st_mode))throw rejected();Os.fsync(fd);}finally{Os.close(fd);}}
 private byte[] readCiphertext()throws Exception{
  boolean base=file.getBaseFile().exists(),backup=new File(file.getBaseFile()+".bak").exists();
  if(!base&&!backup){if(new File(file.getBaseFile()+".new").exists())throw rejected();return null;}
  byte[] bytes;try(InputStream in=file.openRead()){bytes=in.readNBytes(32769);}if(bytes.length>32768)throw rejected();syncDirectory();return bytes;
 }
 private void writeCiphertext(byte[] bytes)throws Exception{
  if(bytes.length>32768)throw rejected();FileOutputStream out=null;
  try{out=file.startWrite();out.write(bytes);out.flush();Os.fsync(out.getFD());file.finishWrite(out);out=null;byte[] committed=readCiphertext();if(committed==null||!MessageDigest.isEqual(bytes,committed))throw rejected();}
  finally{if(out!=null)file.failWrite(out);}
 }
 EnrollmentJournal.Session prepare(String serverUrl)throws Exception{synchronized(ProfileStore.class){ProfileStore.requireEnrollmentIdle(context);return journal.prepare(serverUrl);}}
 EnrollmentJournal.Session session()throws Exception{synchronized(ProfileStore.class){return journal.session();}}
 void bind(byte[] binding)throws Exception{synchronized(ProfileStore.class){journal.bind(binding);}}
 byte[] accept(byte[] binding,byte[] request,byte[] envelope)throws Exception{synchronized(ProfileStore.class){return journal.accept(binding,request,envelope);}}
 void finish(byte[] binding,byte[] request,byte[] receipt)throws Exception{synchronized(ProfileStore.class){journal.finish(binding,request,receipt);}}
 boolean ready()throws Exception{synchronized(ProfileStore.class){return journal.ready();}}
 byte[] profile()throws Exception{synchronized(ProfileStore.class){return journal.profile();}}
}
