package dev.readb.handover;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.util.Arrays;
import javax.crypto.*;
import javax.crypto.spec.*;

/** Versioned bounded encrypted transport. Contains no Android state or credentials. */
public final class HandoverProtocol {
 public static final int MAX_PAYLOAD=65536,MAX_REQUEST=2048,MAX_ENVELOPE=68000;
 private static final int REQUEST=0x52445131,ENVELOPE=0x52444531;
 private static final SecureRandom RANDOM=new SecureRandom();
 private static final OAEPParameterSpec OAEP=new OAEPParameterSpec("SHA-256","MGF1",MGF1ParameterSpec.SHA1,PSource.PSpecified.DEFAULT);
 public static final class Request {
  public final byte[] nonce,publicKey;
  Request(byte[] nonce,byte[] publicKey){this.nonce=nonce;this.publicKey=publicKey;}
 }
 private HandoverProtocol(){}
 public static byte[] random(int length){byte[] b=new byte[length];RANDOM.nextBytes(b);return b;}
 public static String sha256(byte[] value)throws GeneralSecurityException{
  byte[] digest=MessageDigest.getInstance("SHA-256").digest(value);StringBuilder out=new StringBuilder();
  for(byte b:digest)out.append(String.format(java.util.Locale.ROOT,"%02x",b&255));return out.toString();
 }
 private static RSAPublicKey publicKey(byte[] encoded)throws Exception{
  PublicKey key=KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(encoded));
  if(!(key instanceof RSAPublicKey)||((RSAPublicKey)key).getModulus().bitLength()<3072||((RSAPublicKey)key).getModulus().bitLength()>4096)throw new IOException("handover_key_rejected");
  return(RSAPublicKey)key;
 }
 public static byte[] request(byte[] nonce,byte[] publicKey)throws Exception{
  if(nonce.length!=32||publicKey.length>1024)throw new IOException("handover_request_rejected");publicKey(publicKey);
  ByteArrayOutputStream bytes=new ByteArrayOutputStream();DataOutputStream out=new DataOutputStream(bytes);
  out.writeInt(REQUEST);out.write(nonce);out.writeInt(publicKey.length);out.write(publicKey);return bytes.toByteArray();
 }
 private static byte[] exact(DataInputStream in,int length,int limit)throws IOException{
  if(length<0||length>limit)throw new IOException("handover_size_rejected");byte[] result=new byte[length];in.readFully(result);return result;
 }
 public static Request parseRequest(byte[] bytes)throws Exception{
  if(bytes==null||bytes.length>MAX_REQUEST)throw new IOException("handover_request_rejected");
  DataInputStream in=new DataInputStream(new ByteArrayInputStream(bytes));if(in.readInt()!=REQUEST)throw new IOException("handover_version_rejected");
  byte[] nonce=exact(in,32,32),key=exact(in,in.readInt(),1024);if(in.read()!=-1)throw new IOException("handover_trailing_data");publicKey(key);return new Request(nonce,key);
 }
 private static byte[] aad(byte[] request,String binding)throws Exception{
  if(binding==null||binding.length()>512||binding.isEmpty())throw new IOException("handover_binding_rejected");
  return("readb-handover-v1\n"+binding+"\n"+sha256(request)).getBytes(StandardCharsets.UTF_8);
 }
 public static byte[] seal(byte[] request,byte[] payload,String binding)throws Exception{
  Request parsed=parseRequest(request);if(payload==null||payload.length>MAX_PAYLOAD)throw new IOException("handover_payload_rejected");
  byte[] key=random(32),iv=random(12);
  try{
   Cipher aes=Cipher.getInstance("AES/GCM/NoPadding");aes.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,iv));aes.updateAAD(aad(request,binding));byte[] sealed=aes.doFinal(payload);
   Cipher rsa=Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");rsa.init(Cipher.ENCRYPT_MODE,publicKey(parsed.publicKey),OAEP);byte[] wrapped=rsa.doFinal(key);
   ByteArrayOutputStream bytes=new ByteArrayOutputStream();DataOutputStream out=new DataOutputStream(bytes);out.writeInt(ENVELOPE);out.write(parsed.nonce);out.writeInt(wrapped.length);out.write(wrapped);out.write(iv);out.writeInt(sealed.length);out.write(sealed);return bytes.toByteArray();
  }finally{Arrays.fill(key,(byte)0);}
 }
 public static byte[] open(byte[] request,byte[] envelope,PrivateKey privateKey,String binding)throws Exception{
  Request parsed=parseRequest(request);if(envelope==null||envelope.length>MAX_ENVELOPE)throw new IOException("handover_envelope_rejected");
  DataInputStream in=new DataInputStream(new ByteArrayInputStream(envelope));if(in.readInt()!=ENVELOPE||!MessageDigest.isEqual(parsed.nonce,exact(in,32,32)))throw new IOException("handover_nonce_rejected");
  byte[] wrapped=exact(in,in.readInt(),1024),iv=exact(in,12,12),sealed=exact(in,in.readInt(),MAX_PAYLOAD+16);if(in.read()!=-1)throw new IOException("handover_trailing_data");
  Cipher rsa=Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");rsa.init(Cipher.DECRYPT_MODE,privateKey,OAEP);byte[] key=rsa.doFinal(wrapped);
  try{if(key.length!=32)throw new IOException("handover_key_rejected");Cipher aes=Cipher.getInstance("AES/GCM/NoPadding");aes.init(Cipher.DECRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,iv));aes.updateAAD(aad(request,binding));return aes.doFinal(sealed);}
  finally{Arrays.fill(key,(byte)0);}
 }
}
