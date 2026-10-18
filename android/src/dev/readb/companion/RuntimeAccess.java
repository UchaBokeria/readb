package dev.readb.companion;
import android.content.Context;
import android.content.pm.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
/** Manifest runtime permissions only; normal/privileged permissions have no runtime prompt. */
final class RuntimeAccess {
 final String[] permissions;
 final String revision;
 RuntimeAccess(Context c) throws Exception {
  PackageInfo info=c.getPackageManager().getPackageInfo(c.getPackageName(),PackageManager.GET_PERMISSIONS);
  TreeSet<String> runtime=new TreeSet<>();
  if(info.requestedPermissions!=null)for(String p:info.requestedPermissions){
   try {PermissionInfo permission=c.getPackageManager().getPermissionInfo(p,0);
   if((permission.protectionLevel&PermissionInfo.PROTECTION_MASK_BASE)==PermissionInfo.PROTECTION_DANGEROUS)runtime.add(p);
   }catch(PackageManager.NameNotFoundException unsupportedOnThisAndroid){}
  }
  permissions=runtime.toArray(new String[0]);
  byte[] hash=java.security.MessageDigest.getInstance("SHA-256").digest(("access-v1\n"+c.getApplicationInfo().targetSdkVersion+"\n"+String.join("\n",permissions)).getBytes(StandardCharsets.UTF_8));
  StringBuilder text=new StringBuilder();for(byte b:hash)text.append(String.format(java.util.Locale.ROOT,"%02x",b&255));revision=text.toString();
 }
 String[] missing(Context c){ArrayList<String> pending=new ArrayList<>();for(String p:permissions)if(c.checkSelfPermission(p)!=PackageManager.PERMISSION_GRANTED)pending.add(p);return pending.toArray(new String[0]);}
}
