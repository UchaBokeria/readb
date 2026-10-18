package dev.readb.handover;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.util.Arrays;
import javax.crypto.*;
import javax.crypto.spec.*;

/** Pure codec. Authentication of the transport, durable storage, profile
 * validation, single-use policy and enabling services belong to later callers. */
public final class EnrollmentDelivery {
 private static final byte[] REQUEST=ascii("RER1"),ENVELOPE=ascii("REE1"),PAYLOAD=ascii("REP1");
 private static final byte[] ACK=ascii("REA1"),FINAL=ascii("REF1");
 private static final byte[] DOMAIN=ascii("readb-enrollment-delivery-v1\0"),RECEIPT_DOMAIN=ascii("readb-enrollment-receipt-v1\0");
 private static final OAEPParameterSpec OAEP=new OAEPParameterSpec("SHA-256","MGF1",MGF1ParameterSpec.SHA1,PSource.PSpecified.DEFAULT);
 private EnrollmentDelivery(){}
 private static byte[] ascii(String s){return s.getBytes(StandardCharsets.US_ASCII);}
 private static IOException rejected(){return new IOException("enrollment_delivery_invalid");}
 private static byte[] hash(byte[] b)throws Exception{return MessageDigest.getInstance("SHA-256").digest(b);}
 private static byte[] concat(byte[]... parts)throws Exception{ByteArrayOutputStream out=new ByteArrayOutputStream();for(byte[] p:parts)out.write(p);return out.toByteArray();}
 private static void blob(DataOutputStream out,byte[] bytes)throws Exception{out.writeInt(bytes.length);out.write(bytes);}
 private static final class Reader {
  final DataInputStream in;
  Reader(byte[] bytes){in=new DataInputStream(new ByteArrayInputStream(bytes));}
  byte[] take(int n)throws Exception{if(n<0||n>in.available())throw rejected();byte[] out=new byte[n];in.readFully(out);return out;}
  void magic(byte[] expected)throws Exception{if(!MessageDigest.isEqual(take(expected.length),expected))throw rejected();}
  byte[] blob(int max)throws Exception{int n=in.readInt();if(n<0||n>max)throw rejected();return take(n);}
  void end()throws Exception{if(in.read()!=-1)throw rejected();}
 }
 private static RSAPublicKey key(byte[] der)throws Exception{
  PublicKey k=KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
  if(!(k instanceof RSAPublicKey))throw rejected();RSAPublicKey rsa=(RSAPublicKey)k;int bits=rsa.getModulus().bitLength();
  if((bits!=3072&&bits!=4096)||!rsa.getPublicExponent().equals(java.math.BigInteger.valueOf(65537))||!Arrays.equals(der,k.getEncoded()))throw rejected();return rsa;
 }
 private static RSAPublicKey parseRequest(byte[] bytes)throws Exception{
  if(bytes==null||bytes.length>2048)throw rejected();Reader r=new Reader(bytes);r.magic(REQUEST);r.take(64);RSAPublicKey k=key(r.blob(1024));r.end();return k;
 }
 private static void context(byte[] bytes)throws Exception{
  if(bytes==null||bytes.length>132)throw rejected();Reader r=new Reader(bytes);r.take(64);byte[] id=r.blob(48);r.end();
  String s=new String(id,StandardCharsets.US_ASCII);if(!s.matches("[a-z0-9][a-z0-9-]{0,47}")||!Arrays.equals(id,ascii(s)))throw rejected();
 }
 public static byte[] request(byte[] installation,byte[] nonce,byte[] publicKey)throws Exception{
  try{
   if(installation.length!=32||nonce.length!=32||publicKey.length>1024)throw rejected();key(publicKey);
   ByteArrayOutputStream bytes=new ByteArrayOutputStream();DataOutputStream out=new DataOutputStream(bytes);out.write(REQUEST);out.write(installation);out.write(nonce);blob(out,publicKey);return bytes.toByteArray();
  }catch(Exception invalid){throw rejected();}
 }
 public static Opened open(byte[] context,byte[] request,byte[] envelope,PrivateKey privateKey)throws Exception{
  byte[] aesKey=null,plaintext=null;
  try{
   context(context);RSAPublicKey publicKey=parseRequest(request);
   if(envelope==null||envelope.length>12288)throw rejected();
   Reader r=new Reader(envelope);r.magic(ENVELOPE);r.magic(hash(request));r.magic(hash(context));byte[] commitment=r.take(32);
   byte[] wrapped=r.blob(512);if(wrapped.length!=(publicKey.getModulus().bitLength()+7)/8)throw rejected();byte[] iv=r.take(12),sealed=r.blob(8248);r.end();if(sealed.length<56)throw rejected();
   Cipher rsa=Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");rsa.init(Cipher.DECRYPT_MODE,privateKey,OAEP);aesKey=rsa.doFinal(wrapped);if(aesKey.length!=32)throw rejected();
   Cipher aes=Cipher.getInstance("AES/GCM/NoPadding");aes.init(Cipher.DECRYPT_MODE,new SecretKeySpec(aesKey,"AES"),new GCMParameterSpec(128,iv));aes.updateAAD(concat(DOMAIN,context,hash(request),commitment));plaintext=aes.doFinal(sealed);
   Reader p=new Reader(plaintext);p.magic(PAYLOAD);byte[] secret=p.take(32);if(!MessageDigest.isEqual(hash(secret),commitment)){Arrays.fill(secret,(byte)0);throw rejected();}
   byte[] profile=null;
   try{profile=p.blob(8192);p.end();if(profile.length==0)throw rejected();Opened opened=new Opened(context,request,envelope,secret,profile);profile=null;return opened;}
   finally{Arrays.fill(secret,(byte)0);if(profile!=null)Arrays.fill(profile,(byte)0);}
  }catch(Exception invalid){throw rejected();}
  finally{if(aesKey!=null)Arrays.fill(aesKey,(byte)0);if(plaintext!=null)Arrays.fill(plaintext,(byte)0);}
 }
 /** Candidate bytes remain private. Caller must validate and durably save profile
  * plus receipt state before emitting ack(); this codec performs no storage. */
 public static final class Opened implements AutoCloseable {
  private final byte[] secret,profile,requestHash,contextHash,envelopeHash;
  private boolean closed;
  private Opened(byte[] context,byte[] request,byte[] envelope,byte[] secret,byte[] profile)throws Exception{
   this.secret=secret.clone();this.profile=profile;requestHash=hash(request);contextHash=hash(context);envelopeHash=hash(envelope);
  }
  private void active()throws Exception{if(closed)throw rejected();}
  public byte[] profileBytes()throws Exception{active();return profile.clone();}
  private byte[] receipt(byte[] kind)throws Exception{
   active();byte[] frame=concat(kind,requestHash,contextHash,envelopeHash);Mac mac=Mac.getInstance("HmacSHA256");mac.init(new SecretKeySpec(secret,"HmacSHA256"));return concat(frame,mac.doFinal(concat(RECEIPT_DOMAIN,frame)));
  }
  public byte[] ack()throws Exception{return receipt(ACK);}
  public void verifyFinal(byte[] frame)throws Exception{if(frame==null||!MessageDigest.isEqual(receipt(FINAL),frame))throw rejected();}
  @Override public void close(){Arrays.fill(secret,(byte)0);Arrays.fill(profile,(byte)0);closed=true;}
  @Override public String toString(){return "[private enrollment delivery]";}
 }
}
