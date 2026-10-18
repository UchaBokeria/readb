package dev.hermes.pixeladbhelper;
import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import dev.readb.handover.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.json.JSONObject;

/** Reporter migration only. The separate WireGuard app and all phone settings stay intact. */
public final class HandoverService extends Service {
 @Override public IBinder onBind(Intent intent){return new HandoverBinder(this,HandoverAndroid.PIXEL,this::payload);}
 private byte[] payload()throws Exception{
  byte[] config;try(InputStream in=new FileInputStream(new File(getFilesDir(),"config.json"))){config=in.readNBytes(8193);}if(config.length>8192)throw new IOException("handover_source_config_rejected");
  try{return new JSONObject().put("schema",1).put("source_package",HandoverAndroid.PIXEL).put("report_token",new JSONObject(new String(config,StandardCharsets.UTF_8)).getString("token")).put("report_enabled",getSharedPreferences("status",0).getBoolean("enabled",true)).toString().getBytes(StandardCharsets.UTF_8);}
  finally{Arrays.fill(config,(byte)0);}
 }
}
