package dev.readb.companion;

import android.app.Activity;
import android.app.Instrumentation;
import android.content.Intent;
import android.graphics.Bitmap;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Base64;
import android.view.PixelCopy;
import android.view.ViewGroup;
import android.webkit.WebView;
import java.io.ByteArrayOutputStream;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/** Development-only capture of this app's real window. No service/profile/input actions. */
public final class UiChecks extends Instrumentation {
    private boolean bottom;
    @Override public void onCreate(Bundle args) {
        super.onCreate(args);bottom=args!=null && "bottom".equals(args.getString("section"));start();
    }
    private void await(CountDownLatch done) throws Exception {
        if(!done.await(15,TimeUnit.SECONDS))throw new Exception("ui_callback_timeout");
    }
    private String evaluate(WebView web,String js) throws Exception {
        CountDownLatch done=new CountDownLatch(1);AtomicReference<String> value=new AtomicReference<>();
        runOnMainSync(()->web.evaluateJavascript(js,r->{value.set(r);done.countDown();}));
        await(done);return value.get();
    }
    @Override public void onStart() {
        Bundle result=new Bundle();Activity activity=null;Bitmap bitmap=null;
        try {
            if(ProfileStore.exists(getTargetContext()))throw new Exception("ui_checks_require_unenrolled_fixture");
            Intent launch=new Intent(getTargetContext(),MainActivity.class)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK|Intent.FLAG_ACTIVITY_CLEAR_TASK);
            activity=startActivitySync(launch);
            final Activity panel=activity;AtomicReference<WebView> view=new AtomicReference<>();
            runOnMainSync(()->view.set((WebView)((ViewGroup)panel.findViewById(android.R.id.content)).getChildAt(0)));
            WebView web=view.get();boolean ready=false;
            long deadline=android.os.SystemClock.elapsedRealtime()+15000;
            while(android.os.SystemClock.elapsedRealtime()<deadline) {
                if("true".equals(evaluate(web,"document.readyState==='complete' && typeof window.updateReadb==='function' && document.getElementById('notifications').textContent!=='Checking…'"))) { ready=true;break; }
                Thread.sleep(100);
            }
            if(!ready)throw new Exception("ui_document_not_ready");
            if(!"true".equals(evaluate(web,"document.documentElement.scrollWidth<=window.innerWidth && [...document.querySelectorAll('button')].every(b=>{const r=b.getBoundingClientRect();return r.left>=0&&r.right<=innerWidth&&r.height>=44})")))
                throw new Exception("ui_horizontal_overflow_or_small_target");
            evaluate(web,bottom?"window.scrollTo(0,document.body.scrollHeight)":"window.scrollTo(0,0)");
            CountDownLatch drawn=new CountDownLatch(1);
            runOnMainSync(()->web.postVisualStateCallback(1,new WebView.VisualStateCallback(){@Override public void onComplete(long id){drawn.countDown();}}));
            await(drawn);waitForIdleSync();
            AtomicInteger width=new AtomicInteger(),height=new AtomicInteger();
            runOnMainSync(()->{width.set(panel.getWindow().getDecorView().getWidth());height.set(panel.getWindow().getDecorView().getHeight());});
            if(width.get()<320 || height.get()<240 || (long)width.get()*height.get()>4000000)throw new Exception("ui_window_bounds_invalid");
            bitmap=Bitmap.createBitmap(width.get(),height.get(),Bitmap.Config.ARGB_8888);
            final Bitmap target=bitmap;CountDownLatch copied=new CountDownLatch(1);AtomicInteger status=new AtomicInteger(-1);
            runOnMainSync(()->PixelCopy.request(panel.getWindow(),target,r->{status.set(r);copied.countDown();},new Handler(Looper.getMainLooper())));
            await(copied);if(status.get()!=PixelCopy.SUCCESS)throw new Exception("ui_window_copy_failed_"+status.get());
            ByteArrayOutputStream png=new ByteArrayOutputStream();bitmap.compress(Bitmap.CompressFormat.PNG,100,png);
            if(png.size()>300000)throw new Exception("ui_capture_too_large");
            result.putString("png_base64",Base64.encodeToString(png.toByteArray(),Base64.NO_WRAP));
            result.putInt("width",width.get());result.putInt("height",height.get());
            result.putString("section",bottom?"bottom":"top");result.putString("result","ui_checks_passed");
        } catch(Throwable error) {
            result.putString("result","ui_checks_failed");
            // Only fixed errors from this test are exposed; never exception/profile content.
            String why=error.getMessage();result.putString("reason",why!=null && why.matches("ui_[a-z_0-9]+")?why:"ui_fixture_failed");
        } finally {
            if(bitmap!=null)bitmap.recycle();
            if(activity!=null){final Activity panel=activity;runOnMainSync(panel::finish);}
        }
        finish("ui_checks_passed".equals(result.getString("result"))?Activity.RESULT_OK:Activity.RESULT_CANCELED,result);
    }
}
