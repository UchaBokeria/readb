package dev.quickshard.adblink;
import android.app.Service;
import android.content.*;
import android.os.IBinder;
import dev.readb.handover.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;
import org.json.JSONObject;

/** Disabled in ordinary APKs. Explicit certificate-pinned development handover only. */
public final class HandoverService extends Service {
 @Override public IBinder onBind(Intent intent){return new HandoverBinder(this,HandoverAndroid.QUEST,this::payload);}
 private byte[] payload()throws Exception{
  Context dps=createDeviceProtectedStorageContext();byte[] config;
  try(InputStream in=new FileInputStream(new File(dps.getFilesDir(),"config.json"))){config=in.readNBytes(8193);}if(config.length>8192)throw new IOException("handover_source_config_rejected");
  String token;try{token=new JSONObject(new String(config,StandardCharsets.UTF_8)).getString("token");}finally{Arrays.fill(config,(byte)0);}
  android.content.SharedPreferences status=dps.getSharedPreferences("status",0);
  Properties properties=new Properties();File consentFile=new File(dps.getFilesDir(),"wireless-consent.properties");
  if(consentFile.isFile()){if(consentFile.length()>4096)throw new IOException("handover_consent_rejected");try(InputStream in=new FileInputStream(consentFile)){properties.load(in);}}
  JSONObject consent=new JSONObject().put("enabled","true".equals(properties.getProperty("enabled"))).put("wake_on_connect","true".equals(properties.getProperty("wake_on_connect"))).put("ssid_sha256",properties.getProperty("ssid_sha256","")).put("bssid_sha256",properties.getProperty("bssid_sha256",""));
  boolean present=BenchPinStore.exists(this),enabled=BenchPinStore.enabled(this);byte[] pin=BenchPinStore.exportStored(this);
  try{return new JSONObject().put("schema",1).put("source_package",HandoverAndroid.QUEST).put("report_token",token).put("report_enabled",status.getBoolean("enabled",false)).put("vpn_config",VpnProfileStore.exists(this)?VpnProfileStore.load(this).toWgQuickString():"").put("vpn_enabled",status.getBoolean("vpn_enabled",false)).put("pin_present",present).put("pin_enabled",enabled).put("pin",new String(pin,StandardCharsets.US_ASCII)).put("consent",consent).toString().getBytes(StandardCharsets.UTF_8);}
  finally{Arrays.fill(pin,(byte)0);}
 }
}
