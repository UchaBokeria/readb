package dev.readb.companion;
public final class EndpointStateTest {
 public static void main(String[] args) {
  EndpointState s=new EndpointState();
  if(s.current(0)!=null)throw new AssertionError("unknown is not a port");
  s.seen(40001,1000);if(s.current(1000)!=40001)throw new AssertionError("observed endpoint");
  if(s.current(46001)!=null)throw new AssertionError("expired endpoint");
  s.seen(40002,50000);s.disabled();if(s.current(50000)!=null)throw new AssertionError("disabled clears endpoint");
  s.seen(40003,60000);if(s.current(59999)!=null)throw new AssertionError("clock reversal");
  s.seen(22,70000);if(s.current(70000)!=null)throw new AssertionError("invalid endpoint clears prior");
  System.out.println("endpoint observations passed");
 }
}
