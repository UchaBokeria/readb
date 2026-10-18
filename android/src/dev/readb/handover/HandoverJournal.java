package dev.readb.handover;
import java.io.*;
import java.security.MessageDigest;
import java.util.Arrays;

/** One export per installed helper. Storage must confirm durability before reads return. */
public final class HandoverJournal {
 public interface Storage { byte[] readConfirmed()throws Exception;void write(byte[] bytes)throws Exception; }
 public interface Payload { byte[] read()throws Exception; }
 private final Storage storage;private final String binding;
 private static final int MAGIC=0x52444a31;
 public HandoverJournal(Storage storage,String binding){this.storage=storage;this.binding=binding;}
 private static final class Record { byte[] request,envelope;boolean ack; }
 private static byte[] blob(DataInputStream in,int max)throws Exception{int n=in.readInt();if(n<0||n>max)throw new IOException("handover_record_rejected");byte[] b=new byte[n];in.readFully(b);return b;}
 private Record read()throws Exception{
  byte[] bytes=storage.readConfirmed();if(bytes==null)return null;if(bytes.length>72000)throw new IOException("handover_record_rejected");
  DataInputStream in=new DataInputStream(new ByteArrayInputStream(bytes));if(in.readInt()!=MAGIC||!in.readUTF().equals(binding))throw new IOException("handover_record_binding_rejected");
  Record r=new Record();r.request=blob(in,HandoverProtocol.MAX_REQUEST);HandoverProtocol.parseRequest(r.request);r.envelope=blob(in,HandoverProtocol.MAX_ENVELOPE);r.ack=in.readBoolean();if(in.read()!=-1)throw new IOException("handover_record_trailing_data");return r;
 }
 private void save(Record r)throws Exception{
  ByteArrayOutputStream bytes=new ByteArrayOutputStream();DataOutputStream out=new DataOutputStream(bytes);out.writeInt(MAGIC);out.writeUTF(binding);out.writeInt(r.request.length);out.write(r.request);out.writeInt(r.envelope.length);out.write(r.envelope);out.writeBoolean(r.ack);storage.write(bytes.toByteArray());
 }
 public synchronized byte[] export(byte[] request,Payload payload)throws Exception{
  HandoverProtocol.parseRequest(request);Record existing=read();
  if(existing!=null){if(!MessageDigest.isEqual(request,existing.request))throw new IOException("handover_already_started");return existing.envelope.clone();}
  byte[] plaintext=payload.read();Record r=new Record();r.request=request.clone();
  try{r.envelope=HandoverProtocol.seal(request,plaintext,binding);}finally{if(plaintext!=null)Arrays.fill(plaintext,(byte)0);}
  save(r);return r.envelope.clone();
 }
 public synchronized void ack(byte[] request,String envelopeSha)throws Exception{
  HandoverProtocol.parseRequest(request);Record r=read();
  if(r==null||!MessageDigest.isEqual(request,r.request)||envelopeSha==null||!envelopeSha.equals(HandoverProtocol.sha256(r.envelope)))throw new IOException("handover_ack_rejected");
  r.ack=true;save(r); // Reconfirmation also covers a lost acknowledgement after rename.
 }
}
