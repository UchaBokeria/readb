package dev.readb.companion;

import android.app.*;
import android.content.*;
import android.os.*;
import android.net.Uri;
import android.provider.Settings;
import android.webkit.*;
import java.io.*;
import java.util.concurrent.*;
import org.json.JSONObject;

/** Local-only themed UI. No remote navigation, credentials or arbitrary native commands. */
public final class MainActivity extends Activity {
    private WebView web;
    private final ExecutorService worker=Executors.newSingleThreadExecutor();
    private volatile boolean destroyed;
    private boolean importing;
    private android.content.SharedPreferences state() { return createDeviceProtectedStorageContext().getSharedPreferences("status",0); }
    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);web=new WebView(this);setContentView(web);
        WebSettings s=web.getSettings();s.setJavaScriptEnabled(true);s.setDomStorageEnabled(false);s.setAllowFileAccess(false);s.setAllowContentAccess(false);s.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        web.addJavascriptInterface(new Bridge(),"Readb");
        web.setWebViewClient(new WebViewClient() {
            @Override public boolean shouldOverrideUrlLoading(WebView view,WebResourceRequest r) { return true; }
            @Override public WebResourceResponse shouldInterceptRequest(WebView view,WebResourceRequest r) {
                String path=r.getUrl().getPath();
                if(!"https".equals(r.getUrl().getScheme()) || !"readb.invalid".equals(r.getUrl().getHost()) || !r.getMethod().equals("GET"))return blocked();
                String asset=path.equals("/")?"companion/index.html":path.equals("/app.js")?"companion/app.js":path.equals("/style.css")?"companion/style.css":null;
                if(asset==null)return blocked();
                try { return new WebResourceResponse(asset.endsWith(".js")?"text/javascript":asset.endsWith(".css")?"text/css":"text/html","UTF-8",getAssets().open(asset)); }
                catch(IOException e) { return blocked(); }
            }
            private WebResourceResponse blocked() { return new WebResourceResponse("text/plain","UTF-8",403,"Forbidden",java.util.Collections.emptyMap(),new ByteArrayInputStream(new byte[0])); }
        });
        web.loadUrl("https://readb.invalid/");
    }
    private void reply(String message) {
        JSONObject response=new JSONObject();
        try {
            response.put("enrolled",ProfileStore.exists(this)).put("vpn_enabled",state().getBoolean("vpn_enabled",false)).put("vpn_active",state().getBoolean("vpn_active",false))
                .put("report_enabled",state().getBoolean("report_enabled",false)).put("report_message",state().getString("report_message","Not started"))
                .put("vpn_message",state().getString("vpn_message","Not started")).put("last_report_epoch",state().getLong("last_report_epoch",0))
                .put("notifications",getSystemService(NotificationManager.class).areNotificationsEnabled())
                .put("secure_settings",checkSelfPermission("android.permission.WRITE_SECURE_SETTINGS")==android.content.pm.PackageManager.PERMISSION_GRANTED)
                .put("message",message);
        } catch(Exception ignored) { return; }
        final String json=response.toString();
        runOnUiThread(()->{if(!destroyed)web.evaluateJavascript("window.updateReadb("+json+")",null);});
    }
    private void start() {
        if(importing) { reply("Finish enrollment import first.");return; }
        if(!ProfileStore.exists(this)) { reply("Import an enrollment profile first.");return; }
        Intent consent=android.net.VpnService.prepare(this);
        if(consent!=null) { startActivityForResult(consent,11);return; }
        try { ProfileStore.enable(this);BootVpnService.startIfEnabled(this);startForegroundService(new Intent(this,ReportService.class));reply("Starting private link."); }
        catch(Exception e) { reply("Could not start. Services may still be stopping; check permissions and try again."); }
    }
    private final class Bridge {
        @JavascriptInterface public void command(String text) {
            if(text==null || text.length()>512 || destroyed)return;
            runOnUiThread(()-> {
                try {
                    JSONObject r=new JSONObject(text);String op=r.getString("op");
                    switch(op) {
                        case "status":reply("");break;
                        case "import":
                            if(state().getBoolean("vpn_enabled",false)||state().getBoolean("report_enabled",false)){reply("Stop the private link before changing its profile.");break;}
                            importing=true;Intent file=new Intent(Intent.ACTION_OPEN_DOCUMENT).setType("application/json").addCategory(Intent.CATEGORY_OPENABLE);startActivityForResult(file,10);break;
                        case "start":start();break;
                        case "stop":
                            state().edit().putBoolean("vpn_enabled",false).putBoolean("report_enabled",false).apply();stopService(new Intent(MainActivity.this,ReportService.class));stopService(new Intent(MainActivity.this,BootVpnService.class));reply("Stopping. Pairing and encrypted profile kept. Wait before importing a different profile.");break;
                        case "notifications":requestPermissions(new String[]{"android.permission.POST_NOTIFICATIONS"},12);break;
                        case "app_settings":startActivity(new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS,Uri.parse("package:"+getPackageName())));break;
                        case "debug_settings":startActivity(new Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS));break;
                        case "vpn_settings":startActivity(new Intent(Settings.ACTION_VPN_SETTINGS));break;
                        default:reply("Unknown action.");
                    }
                } catch(Exception e) { reply("That action is unavailable on this device."); }
            });
        }
    }
    @Override protected void onActivityResult(int request,int result,Intent data) {
        super.onActivityResult(request,result,data);
        if(request==11) { if(result==RESULT_OK)start();else reply("VPN permission was not granted.");return; }
        if(request==10)importing=false;
        if(request==10 && result==RESULT_OK && data!=null && data.getData()!=null) {
            Uri uri=data.getData();
            importing=true;
            worker.execute(()-> {
                try(InputStream in=getContentResolver().openInputStream(uri)) {
                    if(in==null)throw new IOException();
                    byte[] bytes=in.readNBytes(8193);
                    ProfileStore.save(this,bytes);java.util.Arrays.fill(bytes,(byte)0);reply("Profile saved in encrypted device storage. Start when ready.");
                } catch(Exception e) { reply("Enrollment refused. Stop services and check the profile; existing data was kept."); }
                finally { runOnUiThread(()->importing=false); }
            });
        }
    }
    @Override protected void onDestroy() { destroyed=true;worker.shutdownNow();if(web!=null){web.removeJavascriptInterface("Readb");web.destroy();}super.onDestroy(); }
}
