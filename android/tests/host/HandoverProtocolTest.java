import dev.readb.handover.HandoverProtocol;
import java.security.*;
import java.util.Arrays;

public final class HandoverProtocolTest {
 static int checks;
 interface Checked { void run() throws Exception; }
 static void reject(Checked c)throws Exception{try{c.run();}catch(Exception expected){checks++;return;}throw new AssertionError("accepted invalid input");}
 public static void main(String[] args)throws Exception{
  KeyPairGenerator generator=KeyPairGenerator.getInstance("RSA");generator.initialize(3072);
  KeyPair recipient=generator.generateKeyPair(),other=generator.generateKeyPair();
  byte[] nonce=new byte[32];new SecureRandom().nextBytes(nonce);
  byte[] request=HandoverProtocol.request(nonce,recipient.getPublic().getEncoded());
  byte[] payload="synthetic profile; not a credential".getBytes(java.nio.charset.StandardCharsets.UTF_8);
  String binding="source.package\nrecipient.package\n"+"a".repeat(64)+"\n"+"b".repeat(64);
  byte[] envelope=HandoverProtocol.seal(request,payload,binding);
  if(!Arrays.equals(payload,HandoverProtocol.open(request,envelope,recipient.getPrivate(),binding)))throw new AssertionError("roundtrip");checks++;
  reject(()->HandoverProtocol.open(request,envelope,other.getPrivate(),binding));
  reject(()->HandoverProtocol.open(request,envelope,recipient.getPrivate(),binding+"changed"));
  byte[] bad=envelope.clone();bad[bad.length-1]^=1;reject(()->HandoverProtocol.open(request,bad,recipient.getPrivate(),binding));
  byte[] changedNonce=nonce.clone();changedNonce[0]^=1;
  byte[] changedRequest=HandoverProtocol.request(changedNonce,recipient.getPublic().getEncoded());
  reject(()->HandoverProtocol.open(changedRequest,envelope,recipient.getPrivate(),binding));
  reject(()->HandoverProtocol.seal(request,new byte[65537],binding));
  reject(()->HandoverProtocol.parseRequest(Arrays.copyOf(request,request.length-1)));
  reject(()->HandoverProtocol.parseRequest(Arrays.copyOf(request,request.length+1)));
  reject(()->HandoverProtocol.request(new byte[31],recipient.getPublic().getEncoded()));
  generator.initialize(2048);KeyPair weak=generator.generateKeyPair();reject(()->HandoverProtocol.request(nonce,weak.getPublic().getEncoded()));
  reject(()->HandoverProtocol.open(request,Arrays.copyOf(envelope,envelope.length+1),recipient.getPrivate(),binding));
  System.out.println("handover protocol checks="+checks);
 }
}
