package dev.readb.handover;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;

/** Private single enrollment record. Storage encrypts and confirms durability.
 * Callers serialize this journal with all profile imports and activation. */
public final class EnrollmentJournal {
 public interface Storage {byte[] readConfirmed()throws Exception;void write(byte[] record)throws Exception;}
 public interface Recipient {byte[] request()throws Exception;PrivateKey key()throws Exception;}
 public interface Validator {void validate(byte[] context,byte[] profile)throws Exception;}
 private final Storage disk;private final Recipient recipient;private final Validator validator;
 private static final int MAGIC=0x52454a31;
 private Record draft;
 private static final class Record {String url;byte[] credential,context=new byte[0],request,envelope=new byte[0],profile=new byte[0],receipt=new byte[0];}
 public EnrollmentJournal(Storage disk,Recipient recipient,Validator validator){this.disk=disk;this.recipient=recipient;this.validator=validator;}
 private static void clear(Record r){if(r!=null){if(r.profile!=null)Arrays.fill(r.profile,(byte)0);if(r.credential!=null)Arrays.fill(r.credential,(byte)0);}}
 private static final class PrivateBytes extends ByteArrayOutputStream {void clear(){Arrays.fill(buf,(byte)0);}}
 private static IOException rejected(){return new IOException("enrollment_store_rejected");}
 private static boolean same(byte[] a,byte[] b){return a!=null&&b!=null&&MessageDigest.isEqual(a,b);}
 private static byte[] blob(DataInputStream in,int max)throws Exception{int n=in.readInt();if(n<0||n>max||n>in.available())throw rejected();byte[] bytes=new byte[n];in.readFully(bytes);return bytes;}
 private static void blob(DataOutputStream out,byte[] bytes)throws Exception{out.writeInt(bytes.length);out.write(bytes);}
 private static void context(byte[] bytes)throws Exception{
  if(bytes==null||bytes.length>116)throw rejected();DataInputStream in=new DataInputStream(new ByteArrayInputStream(bytes));byte[] fixed=new byte[64];in.readFully(fixed);byte[] id=blob(in,48);
  if(in.read()!=-1||!new String(id,StandardCharsets.US_ASCII).matches("[a-z0-9][a-z0-9-]{0,47}"))throw rejected();
 }
 private Record read()throws Exception{
  byte[] bytes=disk.readConfirmed();if(bytes==null)return null;
  try{
   if(bytes.length>25000)throw rejected();DataInputStream in=new DataInputStream(new ByteArrayInputStream(bytes));if(in.readInt()!=MAGIC)throw rejected();
   Record r=new Record();r.url=in.readUTF();if(!r.url.equals(url(r.url)))throw rejected();r.credential=blob(in,32);if(r.credential.length!=32)throw rejected();r.context=blob(in,116);if(r.context.length!=0)context(r.context);r.request=blob(in,2048);r.envelope=blob(in,12288);r.profile=blob(in,8192);r.receipt=blob(in,132);
   if(in.read()!=-1||r.request.length<450||(r.context.length==0&&r.envelope.length!=0)||(r.envelope.length==0)!=(r.profile.length==0)||(r.receipt.length!=0&&(r.receipt.length!=132||r.envelope.length==0)))throw rejected();return r;
  }finally{Arrays.fill(bytes,(byte)0);}
 }
 private void save(Record r)throws Exception{
  PrivateBytes bytes=new PrivateBytes();DataOutputStream out=new DataOutputStream(bytes);out.writeInt(MAGIC);out.writeUTF(r.url);blob(out,r.credential);blob(out,r.context);blob(out,r.request);blob(out,r.envelope);blob(out,r.profile);blob(out,r.receipt);byte[] record=bytes.toByteArray();
  byte[] confirmed=null;try{disk.write(record);confirmed=disk.readConfirmed();if(!same(record,confirmed))throw rejected();}finally{Arrays.fill(record,(byte)0);if(confirmed!=null)Arrays.fill(confirmed,(byte)0);bytes.clear();}
 }
 private Record require(byte[] context,byte[] request)throws Exception{Record r=read();if(r==null||!same(context,r.context)||!same(request,r.request)){clear(r);throw rejected();}return r;}
 private EnrollmentDelivery.Opened open(Record r)throws Exception{
  EnrollmentDelivery.Opened opened=EnrollmentDelivery.open(r.context,r.request,r.envelope,recipient.key());byte[] candidate=null;
  try{candidate=opened.profileBytes();validator.validate(r.context,candidate);if(!same(candidate,r.profile))throw rejected();return opened;}
  catch(Exception failure){opened.close();throw failure;}finally{if(candidate!=null)Arrays.fill(candidate,(byte)0);}
 }
 /** Private transport session. Never send credential to UI, logs or URL fields. */
 public static final class Session implements AutoCloseable {
  private final String url;private final byte[] request,credential,context;
  private Session(Record r){url=r.url;request=r.request.clone();credential=r.credential.clone();context=r.context.clone();}
  public String url(){return url;}public byte[] request(){return request.clone();}public byte[] credential(){return credential.clone();}public byte[] context(){return context.clone();}
  @Override public void close(){Arrays.fill(credential,(byte)0);}
  @Override public String toString(){return "[private enrollment session]";}
 }
 private static String url(String value)throws Exception{
  try{
  if(value==null||value.length()>2048)throw rejected();java.net.URI u=new java.net.URI(value);
  if(!"https".equals(u.getScheme())||u.getHost()==null||u.getRawUserInfo()!=null||u.getRawQuery()!=null||u.getRawFragment()!=null||u.getPort()>65535||u.getPort()==0||!u.normalize().equals(u))throw rejected();
  String path=u.getRawPath();if(path!=null&&!path.isEmpty()&&!path.equals("/"))throw rejected();
  return new java.net.URI("https",null,u.getHost().toLowerCase(java.util.Locale.ROOT),u.getPort()==443?-1:u.getPort(),"/",null,null).toASCIIString();
  }catch(Exception invalid){throw rejected();}
 }
 public synchronized Session prepare(String serverUrl)throws Exception{
  String canonical=url(serverUrl);Record r=read();if(r==null)r=draft;
  if(r==null){r=new Record();r.url=canonical;r.credential=new byte[32];new SecureRandom().nextBytes(r.credential);r.request=recipient.request();draft=r;}
  try{if(!canonical.equals(r.url))throw rejected();save(r);if(draft!=r)clear(draft);draft=null;return new Session(r);}finally{if(r!=draft)clear(r);}
 }
 public synchronized Session session()throws Exception{Record r=read();if(r==null)throw rejected();try{return new Session(r);}finally{clear(r);}}
 public synchronized void bind(byte[] context)throws Exception{
  context(context);Record r=read();try{if(r==null)throw rejected();if(r.context.length!=0&&!same(r.context,context))throw rejected();r.context=context.clone();save(r);}finally{clear(r);}
 }
 public synchronized byte[] accept(byte[] context,byte[] request,byte[] envelope)throws Exception{
  Record r=require(context,request);try{
  if(r.envelope.length!=0){if(!same(envelope,r.envelope))throw rejected();try(EnrollmentDelivery.Opened opened=open(r)){save(r);return opened.ack();}}
  try(EnrollmentDelivery.Opened opened=EnrollmentDelivery.open(context,request,envelope,recipient.key())){
   byte[] profile=opened.profileBytes();try{validator.validate(context,profile);r.profile=profile;r.envelope=envelope.clone();save(r);return opened.ack();}finally{Arrays.fill(profile,(byte)0);}
  }
  }finally{clear(r);}
 }
 public synchronized void finish(byte[] context,byte[] request,byte[] receipt)throws Exception{
  Record r=require(context,request);try{if(r.envelope.length==0)throw rejected();try(EnrollmentDelivery.Opened opened=open(r)){
   opened.verifyFinal(receipt);if(r.receipt.length!=0&&!same(r.receipt,receipt))throw rejected();r.receipt=receipt.clone();save(r);
  }}finally{clear(r);}
 }
 public synchronized boolean ready()throws Exception{Record r=read();try{if(r==null||r.receipt.length==0)return false;try(EnrollmentDelivery.Opened opened=open(r)){opened.verifyFinal(r.receipt);return true;}}finally{clear(r);}}
 public synchronized byte[] profile()throws Exception{Record r=read();try{if(r==null||r.receipt.length==0)throw rejected();try(EnrollmentDelivery.Opened opened=open(r)){opened.verifyFinal(r.receipt);return r.profile.clone();}}finally{clear(r);}}
 @Override public String toString(){return "[private enrollment journal]";}
}
