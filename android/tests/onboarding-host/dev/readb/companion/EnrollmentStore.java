package dev.readb.companion;

import android.content.Context;
import dev.readb.handover.EnrollmentJournal;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;

/** Test-only Android boundary. Uses the real private journal and delivery codec. */
final class EnrollmentStore {
 static volatile EnrollmentStore fixture;
 final Disk disk=new Disk();final EnrollmentJournal journal;
 static final class Disk implements EnrollmentJournal.Storage {
  volatile byte[] bytes;volatile int writes,failWriteAt;
  public byte[] readConfirmed(){return bytes==null?null:bytes.clone();}
  public void write(byte[] value)throws Exception{writes++;if(writes==failWriteAt)throw new java.io.IOException("synthetic_no_space");bytes=value.clone();}
 }
 EnrollmentStore(Path dir)throws Exception{
  byte[] request=Files.readAllBytes(dir.resolve("request")),profile=Files.readAllBytes(dir.resolve("expected-profile")),context=Files.readAllBytes(dir.resolve("context"));
  PrivateKey key=KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(dir.resolve("private-key"))));
  journal=new EnrollmentJournal(disk,new EnrollmentJournal.Recipient(){public byte[] request(){return request.clone();}public PrivateKey key(){return key;}},(c,p)->{if(!Arrays.equals(c,context)||!Arrays.equals(p,profile))throw new java.io.IOException("synthetic_profile_mismatch");});
 }
 static EnrollmentStore get(Context ignored){return fixture;}
 EnrollmentJournal.Session prepare(String url)throws Exception{return journal.prepare(url);}
 EnrollmentJournal.Session session()throws Exception{return journal.session();}
 void bind(byte[] context)throws Exception{journal.bind(context);}
 byte[] accept(byte[] context,byte[] request,byte[] envelope)throws Exception{return journal.accept(context,request,envelope);}
 void finish(byte[] context,byte[] request,byte[] receipt)throws Exception{journal.finish(context,request,receipt);}
 boolean ready()throws Exception{return journal.ready();}
}
