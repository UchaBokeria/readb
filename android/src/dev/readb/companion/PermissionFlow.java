package dev.readb.companion;
/** One explicit review. Each declined OS request is visited at most once. */
final class PermissionFlow {
 enum Step { RUNTIME, NOTIFICATIONS, VPN, DEBUG_SETTINGS, DONE }
 private int cursor;
 Step next(boolean runtimeReady,boolean notificationsReady,boolean vpnReady,boolean debugReady){
  boolean[] ready={runtimeReady,notificationsReady,vpnReady,debugReady};
  while(cursor<ready.length){int i=cursor++;if(!ready[i])return Step.values()[i];}
  return Step.DONE;
 }
}
