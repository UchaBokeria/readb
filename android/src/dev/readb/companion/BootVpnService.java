package dev.readb.companion;

import android.app.*;
import android.content.*;
import android.net.*;
import com.wireguard.android.backend.GoBackend;
import com.wireguard.android.backend.Tunnel;
import java.util.concurrent.*;

/** Official userspace backend with a device-protected, dedicated remote-ADB profile. */
public final class BootVpnService extends GoBackend.VpnService {
    // Global backend future in the official library requires serialization across service instances.
    private final VpnActor actor = new VpnActor();
    private GoBackend backend;
    private int failures;
    private long nextAttempt;
    private volatile boolean revoked;
    private ConnectivityManager connectivity;
    private ConnectivityManager.NetworkCallback networks;
    private final Tunnel tunnel = new Tunnel() {
        public String getName() { return "readb"; }
        public void onStateChange(Tunnel.State state) { if (!revoked) { createDeviceProtectedStorageContext().getSharedPreferences("status", 0).edit().putBoolean("vpn_active", state == Tunnel.State.UP).apply(); status(state == Tunnel.State.UP ? "Private VPN active." : "Private VPN reconnecting."); } }
    };

    static void startIfEnabled(Context context) {
        Context dps = context.createDeviceProtectedStorageContext();
        if (ProfileStore.exists(context) && dps.getSharedPreferences("status", 0).getBoolean("vpn_enabled", false))
            context.startForegroundService(new Intent(context, BootVpnService.class));
    }
    private void status(String message) {
        createDeviceProtectedStorageContext().getSharedPreferences("status", 0).edit().putString("vpn_message", message).apply();
    }

    @Override public void onCreate() {
        ProfileStore.serviceStarting(this);
        createDeviceProtectedStorageContext().getSharedPreferences("status",0).edit().putBoolean("vpn_active",false).apply();
        // Completes GoBackend's service future before any backend can attempt explicit startup.
        actor.initialize(() -> BootVpnService.super.onCreate());
        NotificationManager manager = getSystemService(NotificationManager.class);
        manager.createNotificationChannel(new NotificationChannel("readb-vpn", "readb VPN", NotificationManager.IMPORTANCE_LOW));
        PendingIntent open = PendingIntent.getActivity(this, 2, new Intent(this, MainActivity.class), PendingIntent.FLAG_IMMUTABLE);
        startForeground(2, new Notification.Builder(this, "readb-vpn")
                .setSmallIcon(android.R.drawable.stat_notify_sync).setContentTitle("readb private link")
                .setContentText("Dedicated link to your readb server").setContentIntent(open).build());
        connectivity = getSystemService(ConnectivityManager.class);
        networks = new ConnectivityManager.NetworkCallback() {
            public void onAvailable(Network network) { changed(); }
            public void onLost(Network network) { changed(); }
            private void changed() {
                actor.execute(() -> { nextAttempt = 0; reconcile(); });
            }
        };
        connectivity.registerNetworkCallback(new NetworkRequest.Builder()
                .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build(), networks);
        actor.repeat(this::reconcile, 15);
    }

    private void reconcile() {
        if (revoked) return;
        if (!ProfileStore.exists(this)) { status("Private VPN profile missing; port reporting remains available."); stopSelf(); return; }
        if (!createDeviceProtectedStorageContext().getSharedPreferences("status", 0).getBoolean("vpn_enabled", false)) { stopSelf(); return; }
        if (System.nanoTime() < nextAttempt) return;
        try {
            if (android.net.VpnService.prepare(this) != null) {
                status("Open readb and approve the private VPN connection."); return;
            }
            if (backend == null) backend = new GoBackend(createDeviceProtectedStorageContext());
            if (backend.getState(tunnel) != Tunnel.State.UP)
                backend.setState(tunnel, Tunnel.State.UP, ProfileStore.vpn(ProfileStore.load(this)));
            failures = 0; nextAttempt = 0;
        } catch (Exception failure) {
            // Never log backend exceptions: config-parser error messages can contain credentials.
            status("Private VPN temporarily unavailable; retrying automatically.");
            failures = Math.min(failures + 1, 3);
            nextAttempt = System.nanoTime() + TimeUnit.SECONDS.toNanos(Math.min(60, 15L << (failures - 1)));
        }
    }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        actor.execute(() -> BootVpnService.super.onStartCommand(intent, flags, startId));
        return START_STICKY;
    }
    @Override public void onRevoke() {
        revoked = true;
        createDeviceProtectedStorageContext().getSharedPreferences("status", 0).edit()
                .putBoolean("vpn_enabled", false).putBoolean("vpn_active",false).putString("vpn_message", "Private VPN permission revoked.").apply();
        stopSelf();
    }
    @Override public void onDestroy() {
        revoked = true;
        createDeviceProtectedStorageContext().getSharedPreferences("status",0).edit().putBoolean("vpn_active",false).apply();
        if (connectivity != null && networks != null) try { connectivity.unregisterNetworkCallback(networks); } catch (RuntimeException ignored) { }
        // Parent only closes its backend handle and resets the global future (Service itself is a no-op).
        // Keep create/start/destroy ordered across replacements, including rapid stop/start.
        actor.close(() -> { try { BootVpnService.super.onDestroy(); } finally { ProfileStore.serviceStopped(this); } });
    }
}
