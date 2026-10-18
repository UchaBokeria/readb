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
    private DebugEndpointObserver debug;
    private RuntimeAccess access;
    private PermissionFlow permissionFlow;
    private static final int ACCESS_RUNTIME=21,ACCESS_NOTIFICATIONS=22,ACCESS_VPN=23,MANUAL_VPN=24;
    private final ExecutorService worker=Executors.newSingleThreadExecutor();
    private volatile boolean destroyed;
    private boolean importing;
    private boolean pageReady;
    private volatile boolean profileReady,setupSaved;
    private boolean setupActive;
    private String setupPhase="idle",setupMessage="";
    private long setupGeneration;
    private OnboardingClient onboarding;
    private final ExecutorService enrollmentWorker=Executors.newSingleThreadExecutor();
    private void refreshProfile(){worker.execute(()->{boolean ready=ProfileStore.exists(this),saved=EnrollmentStore.present(this);runOnUiThread(()->{if(destroyed)return;profileReady=ready;setupSaved=saved;reply("");});});}
    private void connectSetup(String address,String code){
        if(setupActive){reply("Setup is already running. You can cancel safely.");return;}
        if(importing||state().getBoolean("vpn_enabled",false)||state().getBoolean("report_enabled",false)){reply("Stop the private link before setting up a device.");return;}
        long generation=++setupGeneration;setupActive=true;
        onboarding=new OnboardingClient(this,(phase,message,active)->runOnUiThread(()->{if(destroyed||generation!=setupGeneration)return;setupPhase=phase;setupMessage=message;setupActive=active;if(!active)refreshProfile();reply("");}));
        OnboardingClient client=onboarding;enrollmentWorker.execute(()->client.run(address,code));reply("");
    }
    private void cancelSetup(){++setupGeneration;if(onboarding!=null)onboarding.cancel();setupActive=false;setupPhase="paused";setupMessage="Setup paused. Saved data was kept. Resume when ready.";refreshProfile();reply("");}
    private android.content.SharedPreferences state() { return createDeviceProtectedStorageContext().getSharedPreferences("status",0); }
    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        getWindow().setDecorFitsSystemWindows(false);
        getWindow().clearFlags(android.view.WindowManager.LayoutParams.FLAG_FULLSCREEN);
        getWindow().setBackgroundDrawable(new android.graphics.drawable.ColorDrawable(android.graphics.Color.rgb(18,24,32)));
        android.view.WindowInsetsController bars=getWindow().getInsetsController();
        if(bars!=null){bars.show(android.view.WindowInsets.Type.systemBars());bars.setSystemBarsAppearance(0,android.view.WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS|android.view.WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS);}
        web=new WebView(this);debug=new DebugEndpointObserver(this);
        try{access=new RuntimeAccess(this);}catch(Exception unavailable){access=null;}
        android.widget.FrameLayout bounds=new android.widget.FrameLayout(this);
        bounds.addView(web,new android.widget.FrameLayout.LayoutParams(-1,-1));setContentView(bounds);
        bounds.setOnApplyWindowInsetsListener((view,insets)->{
            android.graphics.Insets safe=insets.getInsets(android.view.WindowInsets.Type.systemBars()|android.view.WindowInsets.Type.displayCutout()|android.view.WindowInsets.Type.ime());
            view.setPadding(safe.left,safe.top,safe.right,safe.bottom);return android.view.WindowInsets.CONSUMED;
        });
        bounds.requestApplyInsets();
        WebSettings s=web.getSettings();s.setJavaScriptEnabled(true);s.setDomStorageEnabled(false);s.setAllowFileAccess(false);s.setAllowContentAccess(false);s.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        web.addJavascriptInterface(new Bridge(),"Readb");
        web.setWebViewClient(new WebViewClient() {
            @Override public void onPageStarted(WebView view,String url,android.graphics.Bitmap icon){pageReady=false;}
            @Override public void onPageFinished(WebView view,String url){if("https://readb.invalid/".equals(url)){pageReady=true;refreshProfile();reply("");}}
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
            Boolean wireless=debug.enabled();Integer remotePort=debug.port();
            response.put("permission_setup_required",access!=null&&!access.revision.equals(accessState().getString("reviewed_revision","")))
                .put("vpn_authorized",vpnAuthorized())
                .put("permission_flow_active",permissionFlow!=null)
                .put("wireless_debugging",wireless==null?JSONObject.NULL:wireless)
                .put("remote_port",remotePort==null?JSONObject.NULL:remotePort)
                .put("port_observed_epoch",remotePort==null?0:debug.observedEpoch());
            response.put("setup_active",setupActive).put("setup_saved",setupSaved).put("setup_phase",setupPhase).put("setup_message",setupMessage);
            response.put("enrolled",profileReady).put("vpn_enabled",state().getBoolean("vpn_enabled",false)).put("vpn_active",state().getBoolean("vpn_active",false))
                .put("report_enabled",state().getBoolean("report_enabled",false)).put("report_message",state().getString("report_message","Not started"))
                .put("vpn_message",state().getString("vpn_message","Not started")).put("last_report_epoch",state().getLong("last_report_epoch",0))
                .put("notifications",getSystemService(NotificationManager.class).areNotificationsEnabled())
                .put("secure_settings",checkSelfPermission("android.permission.WRITE_SECURE_SETTINGS")==android.content.pm.PackageManager.PERMISSION_GRANTED)
                .put("message",message);
        } catch(Exception ignored) { return; }
        final String json=response.toString();
        runOnUiThread(()->{if(!destroyed&&pageReady)web.evaluateJavascript("if(typeof window.updateReadb===\"function\") window.updateReadb("+json+")",null);});
    }
    private android.content.SharedPreferences accessState(){return createDeviceProtectedStorageContext().getSharedPreferences("access-review",0);}
    private boolean vpnAuthorized(){try{return android.net.VpnService.prepare(this)==null;}catch(RuntimeException unavailable){return false;}}
    private void reviewedAccess(){if(access!=null)accessState().edit().putString("reviewed_revision",access.revision).apply();}
    private void openNotifications(int request){
        try{if(request==0)startActivity(AppSettings.notifications(this));else startActivityForResult(AppSettings.notifications(this),request);}
        catch(ActivityNotFoundException|SecurityException unavailable){startActivity(AppSettings.details(this));if(request!=0)advanceAccess();}
    }
    private void openDebugSettings(){
        try{startActivity(DebugSettings.route(this));}
        catch(ActivityNotFoundException|SecurityException unavailable){startActivity(DebugSettings.fallback());reply("Open Wireless debugging in Developer options. Direct navigation is unavailable on this device.");}
    }
    private void approveVpn(){
        if(permissionFlow!=null){reply("Finish the current Android prompt first.");return;}
        try{Intent consent=android.net.VpnService.prepare(this);if(consent==null)reply("readb VPN access is already approved. The tunnel starts separately.");else startActivityForResult(consent,MANUAL_VPN);}
        catch(RuntimeException unavailable){reply("VPN approval is unavailable. Check Android VPN settings.");}
    }
    private void advanceAccess(){
        if(permissionFlow==null)return;
        if(access==null){permissionFlow=null;reply("Required access could not be read. Open App permissions to check.");return;}
        String[] missing=access.missing(this);
        boolean notificationPromptPossible=checkSelfPermission("android.permission.POST_NOTIFICATIONS")!=android.content.pm.PackageManager.PERMISSION_GRANTED;
        PermissionFlow.Step next=permissionFlow.next(missing.length==0,notificationPromptPossible||getSystemService(NotificationManager.class).areNotificationsEnabled(),vpnAuthorized(),Boolean.TRUE.equals(debug.enabled()));
        try{switch(next){
            case RUNTIME:requestPermissions(missing,ACCESS_RUNTIME);break;
            case NOTIFICATIONS:openNotifications(ACCESS_NOTIFICATIONS);break;
            case VPN:
                Intent consent=android.net.VpnService.prepare(this);
                if(consent==null)advanceAccess();else startActivityForResult(consent,ACCESS_VPN);
                break;
            case DEBUG_SETTINGS:permissionFlow=null;openDebugSettings();reply("Turn on Wireless debugging, then return to readb. Your tunnel has not been started.");break;
            case DONE:permissionFlow=null;reply("Access review finished. Any declined access can be reviewed in Settings. The tunnel starts separately.");break;
        }}catch(RuntimeException unavailable){permissionFlow=null;reply("That Android prompt is unavailable. Review device access in Settings.");}
    }
    private void start() {
        if(importing||setupActive) { reply("Finish device setup first.");return; }
        if(!profileReady) { reply("Connect this device to your server first.");return; }
        Intent consent=android.net.VpnService.prepare(this);
        if(consent!=null) { startActivityForResult(consent,11);return; }
        try { ProfileStore.enable(this);BootVpnService.startIfEnabled(this);startForegroundService(new Intent(this,ReportService.class));reply("Starting private link."); }
        catch(Exception e) { reply("Could not start. Services may still be stopping; check permissions and try again."); }
    }
    private final class Bridge {
        @JavascriptInterface public void command(String text) {
            if(text==null || text.length()>4096 || destroyed)return;
            runOnUiThread(()-> {
                try {
                    JSONObject r=new JSONObject(text);String op=r.getString("op");
                    switch(op) {
                        case "status":refreshProfile();break;
                        case "setup_connect":connectSetup(r.getString("server"),r.getString("code"));break;
                        case "setup_resume":connectSetup(null,null);break;
                        case "setup_cancel":cancelSetup();break;
                        case "import":
                            if(setupActive||setupSaved){reply("A saved device setup is present. Resume it; existing data was kept.");break;}
                            if(state().getBoolean("vpn_enabled",false)||state().getBoolean("report_enabled",false)){reply("Stop the private link before changing its profile.");break;}
                            importing=true;Intent file=new Intent(Intent.ACTION_OPEN_DOCUMENT).setType("application/json").addCategory(Intent.CATEGORY_OPENABLE);startActivityForResult(file,10);break;
                        case "start":start();break;
                        case "stop":
                            state().edit().putBoolean("vpn_enabled",false).putBoolean("report_enabled",false).apply();stopService(new Intent(MainActivity.this,ReportService.class));stopService(new Intent(MainActivity.this,BootVpnService.class));reply("Stopping. Pairing and encrypted profile kept. Wait before importing a different profile.");break;
                        case "notifications":case "notifications_settings":openNotifications(0);break;
                        case "app_settings":startActivity(AppSettings.details(MainActivity.this));break;
                        case "permissions_settings":startActivity(AppSettings.permissions(MainActivity.this));reply("On App info, choose Permissions. Android protects the deeper permission page from direct app links.");break;
                        case "approve_vpn":approveVpn();break;
                        case "request_access":
                            if(permissionFlow!=null){reply("Finish the current Android prompt first.");break;}
                            reviewedAccess();permissionFlow=new PermissionFlow();advanceAccess();break;
                        case "finish_access":reviewedAccess();reply("");break;
                        case "debug_settings":
                            openDebugSettings();break;
                        case "vpn_settings":startActivity(new Intent(Settings.ACTION_VPN_SETTINGS));break;
                        default:reply("Unknown action.");
                    }
                } catch(Exception e) { reply("That action is unavailable on this device."); }
            });
        }
    }
    @Override protected void onActivityResult(int request,int result,Intent data) {
        super.onActivityResult(request,result,data);
        if(request==ACCESS_NOTIFICATIONS||request==ACCESS_VPN){advanceAccess();return;}
        if(request==MANUAL_VPN){reply(result==RESULT_OK?"readb VPN approved. Finish device setup and choose Start private link when ready.":"VPN access was not approved. Your saved setup was kept.");return;}
        if(request==11) { if(result==RESULT_OK)start();else reply("VPN permission was not granted.");return; }
        if(request==10)importing=false;
        if(request==10 && result==RESULT_OK && data!=null && data.getData()!=null) {
            Uri uri=data.getData();
            importing=true;
            worker.execute(()-> {
                try(InputStream in=getContentResolver().openInputStream(uri)) {
                    if(in==null)throw new IOException();
                    byte[] bytes=in.readNBytes(8193);
                    ProfileStore.save(this,bytes);java.util.Arrays.fill(bytes,(byte)0);profileReady=true;reply("Profile saved in encrypted device storage. Start when ready.");
                } catch(Exception e) { reply("Enrollment refused. Stop services and check the profile; existing data was kept."); }
                finally { runOnUiThread(()->importing=false); }
            });
        }
    }
    @Override public void onRequestPermissionsResult(int request,String[] permissions,int[] results){super.onRequestPermissionsResult(request,permissions,results);if(request==ACCESS_RUNTIME)advanceAccess();else reply("");}
    @Override protected void onStart(){super.onStart();if(debug!=null){debug.start();refreshProfile();reply("");}}
    @Override protected void onStop(){if(debug!=null)debug.stop();super.onStop();}
    @Override protected void onDestroy() { destroyed=true;++setupGeneration;if(onboarding!=null)onboarding.cancel();enrollmentWorker.shutdownNow();worker.shutdownNow();if(web!=null){web.removeJavascriptInterface("Readb");web.destroy();}super.onDestroy(); }
}
