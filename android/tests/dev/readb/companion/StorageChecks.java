package dev.readb.companion;

import android.app.Instrumentation;
import android.os.Bundle;
import com.wireguard.crypto.KeyPair;
import java.io.File;
import java.nio.file.Files;
import java.util.Arrays;
import org.json.JSONObject;

/** Development-only, synchronous checks. Never starts reporting or the VPN. */
public final class StorageChecks extends Instrumentation {
    @Override public void onCreate(Bundle args) { super.onCreate(args);start(); }
    private void check(boolean value) { if(!value)throw new AssertionError("storage_check_failed"); }
    @Override public void onStart() {
        File file=new File(getTargetContext().createDeviceProtectedStorageContext().getFilesDir(),"profile.enc");
        byte[] original=null;boolean existed=file.isFile();Bundle result=new Bundle();
        try {
            if(existed)original=Files.readAllBytes(file.toPath());
            KeyPair device=new KeyPair(),server=new KeyPair();
            String token="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
            JSONObject profile=new JSONObject().put("schema",1).put("device_id","storage-test").put("server_peer","192.168.253.2").put("server_port",19192)
                .put("device_address","192.168.253.5").put("token",token).put("private_key",device.getPrivateKey().toBase64())
                .put("server_public_key",server.getPublicKey().toBase64()).put("endpoint","192.0.2.1:51820").put("keep_awake",true).put("prevent_lock",true);
            byte[] plaintext=profile.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
            ProfileStore.save(getTargetContext(),plaintext);
            byte[] first=Files.readAllBytes(file.toPath());
            check(!new String(first,java.nio.charset.StandardCharsets.ISO_8859_1).contains(token));
            check(ProfileStore.load(getTargetContext()).getString("token").equals(token));
            ProfileStore.save(getTargetContext(),plaintext);
            byte[] second=Files.readAllBytes(file.toPath());check(!Arrays.equals(first,second));
            boolean rejected=false;
            try { ProfileStore.save(getTargetContext(),"{\"token\":\"invalid\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8)); }
            catch(Exception expected) { rejected=true; }
            check(rejected && Arrays.equals(second,Files.readAllBytes(file.toPath())));
            second[second.length-1]^=1;Files.write(file.toPath(),second);rejected=false;
            try { ProfileStore.load(getTargetContext()); } catch(Exception expected) { rejected=true; }
            check(rejected);Files.write(file.toPath(),first);
            check(ProfileStore.load(getTargetContext()).getString("token").equals(token));
            Arrays.fill(plaintext,(byte)0);result.putString("result","storage_checks_passed");result.putInt("checks",6);
        } catch(Throwable e) { result.putString("result","storage_checks_failed"); }
        finally {
            try { if(existed && original!=null)Files.write(file.toPath(),original);else if(!existed)Files.deleteIfExists(file.toPath()); }
            catch(Exception e) { result.putString("result","storage_restore_failed"); }
        }
        finish("storage_checks_passed".equals(result.getString("result"))?-1:0,result);
    }
}
