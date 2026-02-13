package anti.rusda;

import android.app.Application;
import android.content.Context;
import android.os.Process;

import anti.rusda.detector.EnvDetectionManager;

/**
 * 应用入口。启动时进行签名校验，防止二次打包：若当前签名与 release 构建时注入的预期值不一致则直接退出。
 */
public class SentryApp extends Application {

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(LocaleHelper.onAttach(base));
    }

    @Override
    public void onCreate() {
        super.onCreate();
        /* 签名校验：release 构建时注入预期 SHA-256，不匹配则退出（Debug 未注入则跳过） */
        try {
            EnvDetectionManager.ensureEnvLoaded();
            if (!EnvDetectionManager.verifyAppSignatureAtStartup(this)) {
                Process.killProcess(Process.myPid());
                System.exit(1);
            }
        } catch (Throwable ignored) {
            /* 库未加载或校验异常时继续启动，避免误杀 */
        }
    }
}
