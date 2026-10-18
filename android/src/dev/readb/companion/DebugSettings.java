package dev.readb.companion;

import android.content.*;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.provider.Settings;
import android.service.quicksettings.TileService;

/** Settings owns navigation. Never inject a private fragment or change a setting. */
final class DebugSettings {
 static Intent fallback(){
  Bundle args=new Bundle();args.putString(":settings:fragment_args_key","toggle_adb_wireless");
  return new Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS)
   .putExtra(":settings:fragment_args_key","toggle_adb_wireless")
   .putExtra(":settings:show_fragment_args",args);
 }
 static Intent route(Context c){
  for(String name:new String[]{"com.android.settings.development.qstile.AdbWirelessDebuggingDevelopmentTile","com.android.settings.development.qstile.DevelopmentTiles$WirelessDebugging"}){
   ComponentName tile=new ComponentName("com.android.settings",name);
   try{
    c.getPackageManager().getServiceInfo(tile,PackageManager.MATCH_DISABLED_COMPONENTS);
    return new Intent(TileService.ACTION_QS_TILE_PREFERENCES).setPackage("com.android.settings").putExtra(Intent.EXTRA_COMPONENT_NAME,tile);
   }catch(PackageManager.NameNotFoundException|SecurityException ignored){}
  }
  return fallback();
 }
}
