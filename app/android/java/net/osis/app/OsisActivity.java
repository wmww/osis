package net.osis.app;

import android.app.Activity;
import android.os.Bundle;
import android.view.WindowManager;

/** The app's one activity: a full-window {@link OsisView}, drawn edge to edge. */
public final class OsisActivity extends Activity {
    static {
        System.loadLibrary("osis_android");
    }

    private OsisView view;

    @Override
    protected void onCreate(Bundle saved) {
        super.onCreate(saved);
        // the view pads for the system bars and the keyboard itself (OsisView.onApplyWindowInsets)
        if (android.os.Build.VERSION.SDK_INT >= 30) {
            getWindow().setDecorFitsSystemWindows(false);
        }
        // the keyboard opens for a tap on a field (OsisView.showKeyboard), not with the window
        getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE | WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_HIDDEN);
        view = new OsisView(this, getFilesDir().getAbsolutePath());
        setContentView(view);
        view.requestFocus();
        if (android.os.Build.VERSION.SDK_INT >= 33) {
            // apps targeting 36 get no onBackPressed: Back comes here
            getOnBackInvokedDispatcher().registerOnBackInvokedCallback(android.window.OnBackInvokedDispatcher.PRIORITY_DEFAULT, this::back);
        }
    }

    /** The app goes back if it can, else the system's Back: to the launcher. */
    private void back() {
        if (!view.back()) {
            moveTaskToBack(true);
        }
    }

    @Override
    @SuppressWarnings("deprecation")
    public void onBackPressed() {
        back();
    }

    @Override
    protected void onDestroy() {
        view.destroy();
        super.onDestroy();
    }
}
