package dev.readb.companion;
import android.content.*;

public final class BootReceiver extends BroadcastReceiver {
    @Override public void onReceive(Context context,Intent intent) {
        String action=intent.getAction();
        if(!Intent.ACTION_BOOT_COMPLETED.equals(action) && !Intent.ACTION_LOCKED_BOOT_COMPLETED.equals(action) && !Intent.ACTION_MY_PACKAGE_REPLACED.equals(action))return;
        if(!ProfileStore.exists(context))return;
        android.content.SharedPreferences state=context.createDeviceProtectedStorageContext().getSharedPreferences("status",0);
        try {
            BootVpnService.startIfEnabled(context);
            if(state.getBoolean("report_enabled",false))context.startForegroundService(new Intent(context,ReportService.class));
        } catch(RuntimeException e) { state.edit().putString("report_message","Boot startup restricted. Open readb to resume.").apply(); }
    }
}
