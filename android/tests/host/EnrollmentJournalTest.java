import dev.readb.handover.EnrollmentJournal;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;

public final class EnrollmentJournalTest {
 interface Action {void run()throws Exception;}
 static int checks;
 static void check(boolean ok){if(!ok)throw new AssertionError("journal safety check failed");checks++;}
 static void reject(Action a)throws Exception{try{a.run();}catch(Exception expected){checks++;return;}throw new AssertionError("unsafe journal operation accepted");}
 static class Disk implements EnrollmentJournal.Storage {
  byte[] bytes,lastAttempt,archived;boolean noSpace,lostReply,readFailure,corrupt,archiveFailure,archiveCopyFailure;
  public byte[] readConfirmed()throws Exception{if(readFailure)throw new java.io.IOException("sync_failure");return bytes==null?null:bytes.clone();}
  public void archive(byte[] value)throws Exception{if(archiveFailure)throw new java.io.IOException("archive_no_space");if(!Arrays.equals(value,bytes))throw new java.io.IOException("archive_conflict");archived=bytes.clone();if(archiveCopyFailure)throw new java.io.IOException("archive_directory_sync_failed");bytes=null;if(lostReply)throw new java.io.IOException("archive_lost_reply");}
  public void write(byte[] value)throws Exception{lastAttempt=value.clone();if(noSpace)throw new java.io.IOException("no_space");bytes=value.clone();if(corrupt)bytes[bytes.length-1]^=1;if(lostReply)throw new java.io.IOException("post_rename_sync_failure");}
 }
 public static void main(String[] args)throws Exception{
  Path dir=Path.of(args[0]);byte[] context=Files.readAllBytes(dir.resolve("context")),request=Files.readAllBytes(dir.resolve("request")),envelope=Files.readAllBytes(dir.resolve("envelope")),profile=Files.readAllBytes(dir.resolve("expected-profile")),ack=Files.readAllBytes(dir.resolve("ack")),receipt=Files.readAllBytes(dir.resolve("final"));
  PrivateKey privateKey=KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(dir.resolve("private-key"))));
  EnrollmentJournal.Recipient keys=new EnrollmentJournal.Recipient(){public byte[] request(){return request.clone();}public PrivateKey key(){return privateKey;}};
  EnrollmentJournal.Validator validator=(c,p)->{if(!Arrays.equals(c,context)||!Arrays.equals(p,profile))throw new java.io.IOException("invalid_profile");};
  Disk bootstrap=new Disk();EnrollmentJournal first=new EnrollmentJournal(bootstrap,keys,validator);bootstrap.noSpace=true;reject(()->first.prepare("https://readb.example.org/"));check(bootstrap.bytes==null);byte[] firstAttempt=bootstrap.lastAttempt.clone();bootstrap.noSpace=false;bootstrap.lostReply=true;reject(()->first.prepare("https://readb.example.org/"));check(Arrays.equals(firstAttempt,bootstrap.bytes));byte[] boundBootstrap=bootstrap.bytes.clone();bootstrap.lostReply=false;
  EnrollmentJournal recovered=new EnrollmentJournal(bootstrap,keys,validator);EnrollmentJournal.Session a=recovered.session();EnrollmentJournal.Session b=recovered.prepare("https://READB.example.org:443");check(Arrays.equals(a.request(),b.request()));check(Arrays.equals(a.credential(),b.credential()));check(Arrays.equals(boundBootstrap,bootstrap.bytes));check(a.context().length==0);reject(()->recovered.accept(context,request,envelope));
  reject(()->recovered.prepare("https://readb.example.org/secret"));reject(()->recovered.prepare("https://readb.example.org/#code"));
  try{recovered.prepare("https://secret-must-not-leak/%");throw new AssertionError();}catch(Exception invalid){check(!invalid.toString().contains("secret-must-not-leak"));}
  byte[] wrongBootstrap=request.clone();wrongBootstrap[0]^=1;reject(()->recovered.abandonBootstrap(wrongBootstrap));
  bootstrap.archiveCopyFailure=true;reject(()->recovered.abandonBootstrap(request));check(Arrays.equals(bootstrap.bytes,boundBootstrap));check(Arrays.equals(bootstrap.archived,boundBootstrap));bootstrap.archiveCopyFailure=false;
  bootstrap.archiveFailure=true;reject(()->recovered.abandonBootstrap(request));check(Arrays.equals(bootstrap.bytes,boundBootstrap));bootstrap.archiveFailure=false;bootstrap.lostReply=true;reject(()->recovered.abandonBootstrap(request));check(bootstrap.bytes==null);check(Arrays.equals(bootstrap.archived,boundBootstrap));bootstrap.lostReply=false;recovered.abandonBootstrap(request);reject(()->recovered.session());check(!Arrays.equals(recovered.prepare("https://other.example.org/").credential(),a.credential()));
  Disk cleanArchive=new Disk();EnrollmentJournal abandon=new EnrollmentJournal(cleanArchive,keys,validator);abandon.prepare("https://readb.example.org/");byte[] originalArchive=cleanArchive.bytes.clone();abandon.abandonBootstrap(request);check(cleanArchive.bytes==null);check(Arrays.equals(cleanArchive.archived,originalArchive));check(!abandon.ready());
  Disk disk=new Disk();EnrollmentJournal initial=new EnrollmentJournal(disk,keys,validator);
  EnrollmentJournal.Session session=initial.prepare("https://readb.example.org/");check(Arrays.equals(session.request(),request));check(session.credential().length==32);check(!initial.ready());initial.bind(context);reject(()->initial.abandonBootstrap(request));reject(()->initial.profile());
  check(Arrays.equals(initial.prepare("https://readb.example.org/").credential(),session.credential()));reject(()->initial.prepare("http://readb.example.org/"));reject(()->initial.prepare("https://user:password@readb.example.org/"));reject(()->initial.prepare("https://readb.example.org/?code=secret"));reject(()->initial.prepare("https://other.example.org/"));
  byte[] requested=disk.bytes.clone();disk.noSpace=true;reject(()->initial.accept(context,request,envelope));check(Arrays.equals(disk.bytes,requested));disk.noSpace=false;
  disk.lostReply=true;reject(()->initial.accept(context,request,envelope));check(!initial.ready());disk.lostReply=false;
  EnrollmentJournal j=new EnrollmentJournal(disk,keys,validator);check(Arrays.equals(j.accept(context,request,envelope),ack));check(!j.ready());
  final EnrollmentJournal pending=j;byte[] wrong=context.clone();wrong[0]^=1;reject(()->pending.bind(wrong));reject(()->pending.accept(wrong,request,envelope));byte[] bad=envelope.clone();bad[bad.length-1]^=1;reject(()->pending.accept(context,request,bad));reject(()->pending.finish(context,request,ack));
  disk.readFailure=true;reject(()->pending.accept(context,request,envelope));reject(()->pending.ready());disk.readFailure=false;
  disk.noSpace=true;reject(()->pending.finish(context,request,receipt));disk.noSpace=false;check(!pending.ready());
  disk.lostReply=true;reject(()->pending.finish(context,request,receipt));disk.lostReply=false;
  j=new EnrollmentJournal(disk,keys,validator);check(j.ready());check(Arrays.equals(j.profile(),profile));j.finish(context,request,receipt);check(Arrays.equals(j.accept(context,request,envelope),ack));
  byte[] valid=disk.bytes.clone();disk.bytes=Arrays.copyOf(valid,valid.length+1);final EnrollmentJournal complete=j;reject(()->complete.ready());disk.bytes=valid;reject(()->complete.abandonBootstrap(request));
  Disk blocked=new Disk();EnrollmentJournal invalid=new EnrollmentJournal(blocked,keys,(c,p)->{throw new java.io.IOException("invalid_profile");});invalid.prepare("https://readb.example.org/");invalid.bind(context);reject(()->invalid.accept(context,request,envelope));check(!invalid.ready());
  Disk corrupt=new Disk();corrupt.corrupt=true;EnrollmentJournal torn=new EnrollmentJournal(corrupt,keys,validator);reject(()->torn.prepare("https://readb.example.org/"));
  System.out.println("Enrollment journal checks="+checks);
 }
}
