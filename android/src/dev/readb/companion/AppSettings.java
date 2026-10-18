package dev.readb.companion;
import android.content.*;
import android.net.Uri;
import android.os.Bundle;
import android.provider.Settings;
final class AppSettings {
 static Intent notifications(Context c){return new Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(Settings.EXTRA_APP_PACKAGE,c.getPackageName());}
 static Intent details(Context c){
  Bundle args=new Bundle();args.putString(":settings:fragment_args_key","permission_settings");
  return new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS,Uri.parse("package:"+c.getPackageName()))
   .putExtra(":settings:fragment_args_key","permission_settings").putExtra(":settings:show_fragment_args",args);
 }
 static Intent permissions(Context c){
  // The deeper permission controller activity is signature-protected on stock Android.
  if(c.checkSelfPermission("android.permission.GRANT_RUNTIME_PERMISSIONS")==android.content.pm.PackageManager.PERMISSION_GRANTED)
   return new Intent("android.intent.action.MANAGE_APP_PERMISSIONS").putExtra(Intent.EXTRA_PACKAGE_NAME,c.getPackageName());
  return details(c);
 }
}
