import dev.readb.handover.*;
import java.security.*;
import java.util.*;

public final class HandoverJournalTest {
 static final class Memory implements HandoverJournal.Storage {
  byte[] bytes;boolean failAfterWrite;int writes;
  public byte[] readConfirmed(){return bytes==null?null:bytes.clone();}
  public void write(byte[] next)throws Exception{bytes=next.clone();writes++;if(failAfterWrite){failAfterWrite=false;throw new java.io.IOException("synthetic_lost_ack");}}
 }
 static int checks;
 interface Checked{void run()throws Exception;}
 static void reject(Checked action)throws Exception{try{action.run();}catch(Exception expected){checks++;return;}throw new AssertionError("bad admission");}
 public static void main(String[] args)throws Exception{
  KeyPairGenerator g=KeyPairGenerator.getInstance("RSA");g.initialize(3072);KeyPair k=g.generateKeyPair();
  byte[] request=HandoverProtocol.request(HandoverProtocol.random(32),k.getPublic().getEncoded());
  String binding="source\nrecipient\n"+"a".repeat(64)+"\n"+"b".repeat(64);
  Memory disk=new Memory();int[] reads={0};HandoverJournal.Payload payload=()->{reads[0]++;return "synthetic".getBytes();};
  HandoverJournal journal=new HandoverJournal(disk,binding);disk.failAfterWrite=true;
  reject(()->journal.export(request,payload));
  byte[] sealed=new HandoverJournal(disk,binding).export(request,payload);
  if(reads[0]!=1)throw new AssertionError("plaintext reexported");checks++;
  byte[] other=HandoverProtocol.request(HandoverProtocol.random(32),k.getPublic().getEncoded());
  reject(()->new HandoverJournal(disk,binding).export(other,payload));
  reject(()->journal.ack(request,"0".repeat(64)));
  disk.failAfterWrite=true;reject(()->journal.ack(request,HandoverProtocol.sha256(sealed)));
  new HandoverJournal(disk,binding).ack(request,HandoverProtocol.sha256(sealed));checks++;
  if(!Arrays.equals(sealed,new HandoverJournal(disk,binding).export(request,payload)))throw new AssertionError("retry changed");checks++;
  reject(()->new HandoverJournal(disk,binding+"changed").export(request,payload));
  byte[] good=disk.bytes;disk.bytes=Arrays.copyOf(good,good.length-1);reject(()->journal.export(request,payload));disk.bytes=good;
  if(reads[0]!=1)throw new AssertionError("unexpected payload read");checks++;
  System.out.println("handover journal checks="+checks);
 }
}
