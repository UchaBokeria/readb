package dev.readb.companion;

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.AtomicFile;
import com.wireguard.config.Config;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import org.json.JSONObject;

/** One device profile. Device-protected ciphertext; key stays in Android Keystore. */
final class ProfileStore {
    private static final java.util.Set<Object> ACTIVE=java.util.Collections.newSetFromMap(new java.util.IdentityHashMap<Object,Boolean>());
    static synchronized boolean serviceStarting(Context c,Object service) {
        try { load(c);ACTIVE.add(service);return true; } catch(Exception unavailable) { return false; }
    }
    static synchronized void serviceStopped(Object service) { ACTIVE.remove(service); }
    static synchronized void enable(Context c) throws Exception {
        if(!ACTIVE.isEmpty())throw new IOException("services_still_stopping");
        load(c);
        if(!c.createDeviceProtectedStorageContext().getSharedPreferences("status",0).edit().putBoolean("vpn_enabled",true).putBoolean("report_enabled",true).commit())throw new IOException("enable_persistence_failed");
    }
    private static final String ALIAS="readb.enrollment.v1";
    private static final byte[] AAD="readb-profile-v1".getBytes(StandardCharsets.UTF_8);
    private static AtomicFile file(Context c) {
        return new AtomicFile(new File(c.createDeviceProtectedStorageContext().getFilesDir(),"profile.enc"));
    }
    static synchronized boolean exists(Context c) {
        if(EnrollmentStore.present(c))try{return !legacyExists(c)&&EnrollmentStore.get(c).ready();}catch(Exception unavailable){return false;}
        return legacyExists(c);
    }
    static boolean legacyExists(Context c) { return file(c).getBaseFile().exists()||new File(file(c).getBaseFile()+".bak").exists()||new File(file(c).getBaseFile()+".new").exists(); }
    static synchronized void requireEnrollmentIdle(Context c)throws Exception {
        android.content.SharedPreferences state=c.createDeviceProtectedStorageContext().getSharedPreferences("status",0);
        if(legacyExists(c))throw new IOException("existing_profile_preserved");
        if(!ACTIVE.isEmpty()||state.getBoolean("vpn_enabled",false)||state.getBoolean("report_enabled",false))throw new IOException("stop_services_before_enrollment");
    }
    private static javax.crypto.SecretKey key(boolean create) throws Exception {
        KeyStore k=KeyStore.getInstance("AndroidKeyStore"); k.load(null);
        if (!k.containsAlias(ALIAS)) {
            if (!create) throw new IOException("profile_key_unavailable");
            KeyGenerator g=KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,"AndroidKeyStore");
            g.init(new KeyGenParameterSpec.Builder(ALIAS,KeyProperties.PURPOSE_ENCRYPT|KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setUnlockedDeviceRequired(false).setUserAuthenticationRequired(false).build());
            g.generateKey();
        }
        return (javax.crypto.SecretKey)k.getKey(ALIAS,null);
    }
    static Config vpn(JSONObject p) throws Exception {
        // No configurable default route: the only peer route is the report/ADB server.
        String config="[Interface]\nPrivateKey = "+p.getString("private_key")+"\nAddress = "+p.getString("device_address")+"/32\n\n[Peer]\nPublicKey = "+p.getString("server_public_key")+"\nEndpoint = "+p.getString("endpoint")+"\nAllowedIPs = "+p.getString("server_peer")+"/32\nPersistentKeepalive = 25\n";
        return Config.parse(new ByteArrayInputStream(config.getBytes(StandardCharsets.UTF_8)));
    }
    private static void validate(JSONObject p) throws Exception {
        JSONObject result=new JSONObject(NativeBridge.call(new JSONObject().put("op","validate_profile").put("profile",p).toString()));
        if (!result.optBoolean("ok")) throw new IOException("invalid_enrollment_profile");
        vpn(p); // Official parser validates actual WireGuard key encoding too.
    }
    static JSONObject validateBytes(byte[] plaintext)throws Exception {
        if(plaintext==null||plaintext.length>8192)throw new IOException("profile_too_large");
        JSONObject p=new JSONObject(new String(plaintext,StandardCharsets.UTF_8));validate(p);return p;
    }
    static synchronized void save(Context c, byte[] plaintext) throws Exception {
        if(EnrollmentStore.present(c))throw new IOException("enrollment_delivery_in_progress");
        android.content.SharedPreferences state=c.createDeviceProtectedStorageContext().getSharedPreferences("status",0);
        if(!ACTIVE.isEmpty() || state.getBoolean("vpn_enabled",false) || state.getBoolean("report_enabled",false))throw new IOException("stop_services_before_import");
        if (plaintext.length>8192) throw new IOException("profile_too_large");
        JSONObject p=new JSONObject(new String(plaintext,StandardCharsets.UTF_8)); validate(p);
        Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.ENCRYPT_MODE,key(true));cipher.updateAAD(AAD);
        byte[] sealed=cipher.doFinal(p.toString().getBytes(StandardCharsets.UTF_8));
        AtomicFile f=file(c);FileOutputStream out=null;
        try {
            out=f.startWrite();out.write(1);out.write(cipher.getIV().length);out.write(cipher.getIV());out.write(sealed);
            f.finishWrite(out);out=null;
        } finally { if(out!=null) f.failWrite(out); }
    }
    private static JSONObject loadDelivered(Context c)throws Exception {
        if(legacyExists(c))throw new IOException("conflicting_profile_preserved");
        byte[] profile=EnrollmentStore.get(c).profile();try{return validateBytes(profile);}finally{java.util.Arrays.fill(profile,(byte)0);}
    }
    static synchronized JSONObject load(Context c) throws Exception {
        if(EnrollmentStore.present(c))return loadDelivered(c);
        byte[] bytes;
        try(InputStream in=file(c).openRead()) { bytes=in.readNBytes(16385); }
        if(bytes.length<30 || bytes.length>16384 || bytes[0]!=1 || bytes[1]!=12) throw new IOException("invalid_profile_ciphertext");
        Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE,key(false),new GCMParameterSpec(128,bytes,2,12));cipher.updateAAD(AAD);
        JSONObject p=new JSONObject(new String(cipher.doFinal(bytes,14,bytes.length-14),StandardCharsets.UTF_8));validate(p);return p;
    }
}
