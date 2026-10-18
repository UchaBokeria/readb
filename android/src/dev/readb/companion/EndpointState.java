package dev.readb.companion;
/** Foreground observation only. Never treats a saved or expired endpoint as current. */
final class EndpointState {
 private Integer port;
 private long observed;
 void seen(int value,long now){port=value>=1024&&value<=65535?value:null;observed=now;}
 long observedAt(){return observed;}
 void disabled(){port=null;}
 Integer current(long now){return port!=null&&now>=observed&&now-observed<=45000?port:null;}
}
