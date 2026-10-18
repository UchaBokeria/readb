package dev.readb.handover;

import android.content.Context;
import android.content.pm.*;
import android.os.Binder;
import android.system.*;
import android.util.AtomicFile;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Properties;

/** Android boundary shared verbatim with the two legacy export builds. */
public final class HandoverAndroid {
 public static final String RECIPIENT="dev.readb.companion",QUEST="dev.quickshard.adblink",PIXEL="dev.hermes.pixeladbhelper";
 public static final String INTERFACE="dev.readb.handover.v1";
 public static final int EXPORT=1,ACK=2;
 private HandoverAndroid(){}
 public static boolean source(String p){return QUEST.equals(p)||PIXEL.equals(p);}
 public static String certificate(Context context,String pkg)throws Exception{
  PackageInfo info=context.getPackageManager().getPackageInfo(pkg,PackageManager.GET_SIGNING_CERTIFICATES);
  if(info.signingInfo==null||info.signingInfo.hasMultipleSigners())throw new SecurityException("handover_signer_rejected");
  Signature[] signatures=info.signingInfo.getApkContentsSigners();if(signatures.length!=1)throw new SecurityException("handover_signer_rejected");
  return HandoverProtocol.sha256(signatures[0].toByteArray());
 }
 public static String binding(Context context,String source)throws Exception{
  if(!source(source))throw new SecurityException("handover_source_rejected");
  byte[] raw;try(InputStream in=context.getAssets().open("handover-trust.properties")){raw=in.readNBytes(4097);}if(raw.length>4096)throw new IOException("handover_trust_rejected");
  Properties pins=new Properties();pins.load(new ByteArrayInputStream(raw));
  String from=pins.getProperty(source,""),to=pins.getProperty(RECIPIENT,"");
  if(!from.matches("[0-9a-f]{64}")||!to.matches("[0-9a-f]{64}")||!from.equals(certificate(context,source))||!to.equals(certificate(context,RECIPIENT)))throw new SecurityException("handover_certificate_rejected");
  return source+"\n"+RECIPIENT+"\n"+from+"\n"+to;
 }
 public static void authorizeRecipient(Context context,String source,int callingUid)throws Exception{
  String[] packages=context.getPackageManager().getPackagesForUid(callingUid);
  if(packages==null||packages.length!=1||!RECIPIENT.equals(packages[0]))throw new SecurityException("handover_caller_rejected");
  if(!source.equals(context.getPackageName()))throw new SecurityException("handover_source_rejected");binding(context,source);
 }
 private static void sync(File directory)throws Exception{
  java.io.FileDescriptor fd=Os.open(directory.getAbsolutePath(),OsConstants.O_RDONLY|OsConstants.O_CLOEXEC,0);
  try{if(!OsConstants.S_ISDIR(Os.fstat(fd).st_mode))throw new IOException("handover_directory_rejected");Os.fsync(fd);}finally{Os.close(fd);}
 }
 public static HandoverJournal.Storage storage(Context c,String name){
  if(!name.matches("[a-z0-9-]+\\.(enc|journal)"))throw new IllegalArgumentException("handover_storage_name_rejected");
  File dir=c.createDeviceProtectedStorageContext().getFilesDir();AtomicFile file=new AtomicFile(new File(dir,name));
  return new HandoverJournal.Storage(){
   public synchronized byte[] readConfirmed()throws Exception{
    if(!file.getBaseFile().isFile()&&!new File(file.getBaseFile()+".bak").isFile())return null;
    byte[] bytes;try(InputStream in=file.openRead()){bytes=in.readNBytes(200001);}if(bytes.length>200000)throw new IOException("handover_storage_rejected");sync(dir);return bytes;
   }
   public synchronized void write(byte[] bytes)throws Exception{
    if(bytes.length>200000)throw new IOException("handover_storage_rejected");FileOutputStream out=null;
    try{
     out=file.startWrite();out.write(bytes);out.flush();Os.fsync(out.getFD());file.finishWrite(out);out=null;
     // AtomicFile may only log failed sync/rename. Confirm exact committed bytes.
     byte[] committed=readConfirmed();
     if(committed==null||!java.security.MessageDigest.isEqual(bytes,committed))throw new IOException("handover_commit_unconfirmed");
    }finally{if(out!=null)file.failWrite(out);}
   }
  };
 }
}
