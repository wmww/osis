package net.osis.app;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.res.Configuration;
import android.graphics.Insets;
import android.view.Choreographer;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.SurfaceHolder;
import android.view.SurfaceView;
import android.view.WindowInsets;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.ExtractedText;
import android.view.inputmethod.InputConnection;
import android.view.inputmethod.InputMethodManager;

/**
 * The app's surface. Everything runs on the UI thread: each callback forwards to Rust
 * (osis-android), which owns the UI and draws into the surface; the input connection reads and
 * edits the focused text there directly, as a TextView's does. Java holds no app state.
 */
final class OsisView extends SurfaceView implements SurfaceHolder.Callback, Choreographer.FrameCallback {
    private final InputMethodManager imm;
    private boolean framePosted;
    /** The extracted-text request an input method monitors, if any (getExtractedText). */
    int extractToken = -1;
    boolean extracting;

    OsisView(Context context, String filesDir) {
        super(context);
        imm = context.getSystemService(InputMethodManager.class);
        setFocusable(true);
        setFocusableInTouchMode(true);
        getHolder().addCallback(this);
        android.view.ViewConfiguration vc = android.view.ViewConfiguration.get(context);
        nativeCreate(filesDir, density(), dark(), android.view.ViewConfiguration.getDoubleTapTimeout(), vc.getScaledDoubleTapSlop());
    }

    private float density() {
        return getResources().getDisplayMetrics().density;
    }

    private boolean dark() {
        int night = getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK;
        return night == Configuration.UI_MODE_NIGHT_YES;
    }

    boolean back() {
        return nativeBack();
    }

    void destroy() {
        nativeDestroy();
    }

    // --- called from Rust

    /** Any thread: run Ui::wake on the UI thread. */
    void wake() {
        post(OsisView::nativeWake);
    }

    /** Draw on the next frame. */
    void requestFrame() {
        if (!framePosted) {
            framePosted = true;
            Choreographer.getInstance().postFrameCallback(this);
        }
    }

    void showKeyboard() {
        imm.showSoftInput(this, 0);
    }

    void hideKeyboard() {
        imm.hideSoftInputFromWindow(getWindowToken(), 0);
    }

    void restartInput() {
        imm.restartInput(this);
    }

    void updateSelection(int selStart, int selEnd, int composeStart, int composeEnd) {
        imm.updateSelection(this, selStart, selEnd, composeStart, composeEnd);
        if (extracting) {
            imm.updateExtractedText(this, extractToken, extracted());
        }
    }

    /** The clipboard's text, or null. */
    String clipboard() {
        ClipboardManager cm = getContext().getSystemService(ClipboardManager.class);
        ClipData clip = cm.getPrimaryClip();
        if (clip == null || clip.getItemCount() == 0) {
            return null;
        }
        CharSequence s = clip.getItemAt(0).coerceToText(getContext());
        return s == null ? null : s.toString();
    }

    void setClipboard(String text) {
        ClipboardManager cm = getContext().getSystemService(ClipboardManager.class);
        cm.setPrimaryClip(ClipData.newPlainText("osis", text));
    }

    ExtractedText extracted() {
        ExtractedText t = new ExtractedText();
        t.text = nativeText();
        int[] o = nativeOffsets();
        t.startOffset = 0;
        t.selectionStart = o[0];
        t.selectionEnd = o[1];
        t.partialStartOffset = -1;
        t.partialEndOffset = -1;
        return t;
    }

    // --- view callbacks

    @Override
    public void surfaceCreated(SurfaceHolder holder) {}

    @Override
    public void surfaceChanged(SurfaceHolder holder, int format, int width, int height) {
        nativeSurface(holder.getSurface(), width, height);
    }

    @Override
    public void surfaceDestroyed(SurfaceHolder holder) {
        nativeSurfaceGone();
    }

    @Override
    public void doFrame(long frameTimeNanos) {
        framePosted = false;
        nativeFrame();
    }

    @Override
    public boolean onTouchEvent(MotionEvent e) {
        int n = e.getPointerCount();
        int[] ids = new int[n];
        int[] tools = new int[n];
        float[] xy = new float[2 * n];
        float[] pressure = new float[n];
        for (int i = 0; i < n; i++) {
            ids[i] = e.getPointerId(i);
            tools[i] = e.getToolType(i);
            xy[2 * i] = e.getX(i);
            xy[2 * i + 1] = e.getY(i);
            pressure[i] = e.getPressure(i);
        }
        return nativeTouch(e.getActionMasked(), e.getActionIndex(), ids, tools, xy, pressure, e.getButtonState(), e.getMetaState(), e.getEventTime());
    }

    private boolean key(KeyEvent e) {
        return nativeKey(e.getAction(), e.getKeyCode(), e.getUnicodeChar(e.getMetaState()), e.getMetaState(), e.getRepeatCount());
    }

    @Override
    public boolean onKeyDown(int keyCode, KeyEvent e) {
        return key(e) || super.onKeyDown(keyCode, e);
    }

    @Override
    public boolean onKeyUp(int keyCode, KeyEvent e) {
        return key(e) || super.onKeyUp(keyCode, e);
    }

    @Override
    public void onWindowFocusChanged(boolean focused) {
        super.onWindowFocusChanged(focused);
        nativeFocus(focused);
    }

    @Override
    public WindowInsets onApplyWindowInsets(WindowInsets insets) {
        if (android.os.Build.VERSION.SDK_INT >= 30) {
            Insets i = insets.getInsets(WindowInsets.Type.systemBars() | WindowInsets.Type.displayCutout() | WindowInsets.Type.ime());
            nativeInsets(i.left, i.top, i.right, i.bottom);
            return WindowInsets.CONSUMED;
        }
        nativeInsets(0, 0, 0, 0);
        return insets;
    }

    @Override
    protected void onConfigurationChanged(Configuration c) {
        super.onConfigurationChanged(c);
        nativeConfig(density(), dark());
    }

    @Override
    public boolean onCheckIsTextEditor() {
        return nativeEditing();
    }

    @Override
    public InputConnection onCreateInputConnection(EditorInfo out) {
        int[] info = nativeEditorInfo();
        if (info == null) {
            return null;
        }
        out.inputType = info[0];
        out.imeOptions = info[1];
        out.initialSelStart = info[2];
        out.initialSelEnd = info[3];
        out.initialCapsMode = info[4];
        extracting = false;
        return new OsisInputConnection(this);
    }

    // --- Rust (osis-android); all on the UI thread but nativeWake's post

    private native void nativeCreate(String filesDir, float density, boolean dark, int doubleTapMs, int doubleTapSlop);
    private native void nativeDestroy();
    private static native void nativeWake();
    private native void nativeSurface(android.view.Surface surface, int width, int height);
    private native void nativeSurfaceGone();
    private native void nativeFrame();
    private native boolean nativeTouch(int action, int index, int[] ids, int[] tools, float[] xy, float[] pressure, int buttons, int meta, long time);
    private native boolean nativeKey(int action, int keyCode, int unicode, int meta, int repeat);
    private native void nativeFocus(boolean focused);
    private native void nativeInsets(int left, int top, int right, int bottom);
    private native void nativeConfig(float density, boolean dark);
    private native boolean nativeBack();
    private native boolean nativeEditing();
    /** inputType, imeOptions, initial selection start and end, caps mode; null: no editor. */
    private native int[] nativeEditorInfo();

    // the input connection's, over the focused text (UTF-16 offsets)
    native String nativeText();
    /** Selection start and end, composing start and end (-1 for none). */
    native int[] nativeOffsets();
    native String nativeTextBefore(int n);
    native String nativeTextAfter(int n);
    native String nativeSelectedText();
    native int nativeCapsMode(int reqModes);
    native boolean nativeReplaceText(String text, int newCursor, boolean composing);
    native boolean nativeSetComposingRegion(int start, int end);
    native boolean nativeFinishComposing();
    native boolean nativeSetSelection(int start, int end);
    native boolean nativeDeleteSurrounding(int before, int after, boolean codePoints);
    native boolean nativeEditorAction(int action);
    native boolean nativeBatch(boolean begin);
    native void nativeCloseConnection();
}
