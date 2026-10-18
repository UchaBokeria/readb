import dev.readb.handover.EnrollmentDelivery;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;

public final class EnrollmentDeliveryTest {
 interface Action { void run() throws Exception; }
 static int rejected;
 static void reject(Action action)throws Exception {try{action.run();}catch(Exception expected){rejected++;return;}throw new AssertionError("malformed delivery accepted");}
 static byte[] read(Path d,String name)throws Exception{return Files.readAllBytes(d.resolve(name));}
 static void write(Path d,String name,byte[] bytes)throws Exception{Files.write(d.resolve(name),bytes);Files.setPosixFilePermissions(d.resolve(name),java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));}
 public static void main(String[] args)throws Exception{
  Path d=Path.of(args[1]);
  if(args[0].equals("init")){
   KeyPairGenerator g=KeyPairGenerator.getInstance("RSA");g.initialize(3072);KeyPair k=g.generateKeyPair();
   write(d,"private-key",k.getPrivate().getEncoded());byte[] installation=new byte[32],nonce=new byte[32];new SecureRandom().nextBytes(installation);new SecureRandom().nextBytes(nonce);
   write(d,"request",EnrollmentDelivery.request(installation,nonce,k.getPublic().getEncoded()));
   g.initialize(2048);KeyPair weak=g.generateKeyPair();reject(()->EnrollmentDelivery.request(installation,nonce,weak.getPublic().getEncoded()));
   java.io.ByteArrayOutputStream malformed=new java.io.ByteArrayOutputStream();java.io.DataOutputStream wire=new java.io.DataOutputStream(malformed);wire.writeBytes("RER1");wire.write(installation);wire.write(nonce);wire.writeInt(weak.getPublic().getEncoded().length);wire.write(weak.getPublic().getEncoded());write(d,"weak-request",malformed.toByteArray());
   reject(()->EnrollmentDelivery.request(new byte[31],nonce,k.getPublic().getEncoded()));return;
  }
  byte[] context=read(d,"context"),request=read(d,"request"),envelope=read(d,"envelope");
  PrivateKey key=KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(read(d,"private-key")));
  EnrollmentDelivery.Opened opened=EnrollmentDelivery.open(context,request,envelope,key);
  if(!Arrays.equals(opened.profileBytes(),read(d,"expected-profile")))throw new AssertionError("profile mismatch");
  if(args[0].equals("final")){
   if(!Arrays.equals(opened.ack(),read(d,"ack")))throw new AssertionError("restart changed ACK");
   opened.verifyFinal(read(d,"final"));reject(()->opened.verifyFinal(read(d,"ack")));byte[] bad=read(d,"final");bad[131]^=1;reject(()->opened.verifyFinal(bad));return;
  }
  write(d,"ack",opened.ack());
  for(int offset:new int[]{0,4,36,68,104,envelope.length-1}){byte[] bad=envelope.clone();bad[offset]^=1;reject(()->EnrollmentDelivery.open(context,request,bad,key));}
  byte[] other=context.clone();other[0]^=1;reject(()->EnrollmentDelivery.open(other,request,envelope,key));
  // Rewrite public hashes too, so these exercise GCM AAD binding itself.
  for(int offset:new int[]{0,32,68}){byte[] changed=context.clone();changed[offset]^=1;byte[] header=envelope.clone();System.arraycopy(MessageDigest.getInstance("SHA-256").digest(changed),0,header,36,32);reject(()->EnrollmentDelivery.open(changed,request,header,key));}
  byte[] otherRequest=request.clone();otherRequest[36]^=1;reject(()->EnrollmentDelivery.open(context,otherRequest,envelope,key));
  for(int offset:new int[]{4,36}){byte[] changed=request.clone();changed[offset]^=1;byte[] header=envelope.clone();System.arraycopy(MessageDigest.getInstance("SHA-256").digest(changed),0,header,4,32);reject(()->EnrollmentDelivery.open(context,changed,header,key));}
  reject(()->EnrollmentDelivery.open(context,request,Arrays.copyOf(envelope,envelope.length-1),key));
  reject(()->EnrollmentDelivery.open(context,request,Arrays.copyOf(envelope,envelope.length+1),key));
  reject(()->EnrollmentDelivery.open(context,request,new byte[12289],key));
  KeyPairGenerator g=KeyPairGenerator.getInstance("RSA");g.initialize(3072);PrivateKey wrong=g.generateKeyPair().getPrivate();reject(()->EnrollmentDelivery.open(context,request,envelope,wrong));
  opened.close();reject(()->opened.ack());reject(()->opened.profileBytes());
  System.out.println("Enrollment delivery rejection checks="+rejected);
 }
}
