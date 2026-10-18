package dev.readb.handover;
import android.content.Context;
import android.os.*;

/** Every transaction checks the real Binder caller, not intent extras or onBind identity. */
public final class HandoverBinder extends Binder {
 private final Context context;private final String source;private final HandoverJournal.Payload payload;
 public HandoverBinder(Context context,String source,HandoverJournal.Payload payload){this.context=context.getApplicationContext();this.source=source;this.payload=payload;}
 @Override protected boolean onTransact(int code,Parcel data,Parcel reply,int flags)throws RemoteException{
  if(code==INTERFACE_TRANSACTION){reply.writeString(HandoverAndroid.INTERFACE);return true;}
  if(code!=HandoverAndroid.EXPORT&&code!=HandoverAndroid.ACK)return super.onTransact(code,data,reply,flags);
  try{
   HandoverAndroid.authorizeRecipient(context,source,Binder.getCallingUid());data.enforceInterface(HandoverAndroid.INTERFACE);
   byte[] request=data.createByteArray();if(request==null||request.length>HandoverProtocol.MAX_REQUEST)throw new SecurityException();
   String sha=code==HandoverAndroid.ACK?data.readString():null;data.enforceNoDataAvail();
   synchronized(HandoverBinder.class){
    HandoverJournal journal=new HandoverJournal(HandoverAndroid.storage(context,"readb-export.journal"),HandoverAndroid.binding(context,source));
    if(code==HandoverAndroid.EXPORT){byte[] envelope=journal.export(request,payload);reply.writeNoException();reply.writeByteArray(envelope);}
    else{journal.ack(request,sha);reply.writeNoException();reply.writeInt(1);}
   }
  }catch(Exception rejected){reply.writeException(new SecurityException("handover_rejected"));}
  return true;
 }
}
