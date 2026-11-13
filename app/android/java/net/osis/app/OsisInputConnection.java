package net.osis.app;

import android.os.Bundle;
import android.os.Handler;
import android.view.KeyEvent;
import android.view.inputmethod.CompletionInfo;
import android.view.inputmethod.CorrectionInfo;
import android.view.inputmethod.ExtractedText;
import android.view.inputmethod.ExtractedTextRequest;
import android.view.inputmethod.InputConnection;
import android.view.inputmethod.InputContentInfo;

/**
 * The keyboard's connection to the focused text: every call goes straight to Rust on the UI
 * thread (kit's ime::android does what BaseInputConnection would), so it always sees the text as
 * it is. Key events go through the view, the same path a hardware keyboard takes.
 */
final class OsisInputConnection implements InputConnection {
    private final OsisView view;

    OsisInputConnection(OsisView view) {
        this.view = view;
    }

    @Override
    public CharSequence getTextBeforeCursor(int n, int flags) {
        return view.nativeTextBefore(n);
    }

    @Override
    public CharSequence getTextAfterCursor(int n, int flags) {
        return view.nativeTextAfter(n);
    }

    @Override
    public CharSequence getSelectedText(int flags) {
        return view.nativeSelectedText();
    }

    @Override
    public int getCursorCapsMode(int reqModes) {
        return view.nativeCapsMode(reqModes);
    }

    @Override
    public ExtractedText getExtractedText(ExtractedTextRequest request, int flags) {
        if ((flags & GET_EXTRACTED_TEXT_MONITOR) != 0) {
            view.extracting = true;
            view.extractToken = request == null ? 0 : request.token;
        }
        return view.extracted();
    }

    @Override
    public boolean deleteSurroundingText(int beforeLength, int afterLength) {
        return view.nativeDeleteSurrounding(beforeLength, afterLength, false);
    }

    @Override
    public boolean deleteSurroundingTextInCodePoints(int beforeLength, int afterLength) {
        return view.nativeDeleteSurrounding(beforeLength, afterLength, true);
    }

    @Override
    public boolean setComposingText(CharSequence text, int newCursorPosition) {
        return view.nativeReplaceText(text.toString(), newCursorPosition, true);
    }

    @Override
    public boolean setComposingRegion(int start, int end) {
        return view.nativeSetComposingRegion(start, end);
    }

    @Override
    public boolean finishComposingText() {
        return view.nativeFinishComposing();
    }

    @Override
    public boolean commitText(CharSequence text, int newCursorPosition) {
        return view.nativeReplaceText(text.toString(), newCursorPosition, false);
    }

    @Override
    public boolean commitCompletion(CompletionInfo text) {
        return false;
    }

    @Override
    public boolean commitCorrection(CorrectionInfo correctionInfo) {
        return false;
    }

    @Override
    public boolean setSelection(int start, int end) {
        return view.nativeSetSelection(start, end);
    }

    @Override
    public boolean performEditorAction(int editorAction) {
        return view.nativeEditorAction(editorAction);
    }

    /** The keyboard's own Select all, Cut, Copy and Paste buttons: the field's own commands, as
     * its shortcuts and the selection menu run them (so the one clipboard path serves them). */
    @Override
    public boolean performContextMenuAction(int id) {
        switch (id) {
            case android.R.id.cut:
                return view.nativeCommand(OsisView.CUT);
            case android.R.id.copy:
                return view.nativeCommand(OsisView.COPY);
            case android.R.id.paste:
                return view.nativeCommand(OsisView.PASTE);
            case android.R.id.selectAll:
                return view.nativeCommand(OsisView.SELECT_ALL);
            default:
                return false;
        }
    }

    @Override
    public boolean beginBatchEdit() {
        return view.nativeBatch(true);
    }

    @Override
    public boolean endBatchEdit() {
        return view.nativeBatch(false);
    }

    @Override
    public boolean sendKeyEvent(KeyEvent event) {
        return view.dispatchKeyEvent(event);
    }

    @Override
    public boolean clearMetaKeyStates(int states) {
        return false;
    }

    @Override
    public boolean reportFullscreenMode(boolean enabled) {
        return false;
    }

    @Override
    public boolean performPrivateCommand(String action, Bundle data) {
        return false;
    }

    @Override
    public boolean requestCursorUpdates(int cursorUpdateMode) {
        return false;
    }

    @Override
    public Handler getHandler() {
        return null;
    }

    @Override
    public void closeConnection() {
        view.extracting = false;
        view.nativeCloseConnection();
    }

    @Override
    public boolean commitContent(InputContentInfo inputContentInfo, int flags, Bundle opts) {
        return false;
    }
}
