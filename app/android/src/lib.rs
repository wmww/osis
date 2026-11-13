//! The osis app on Android (experimental; notes/android.md): the same UI as desktop in a View of
//! our own (java/: `OsisActivity`, `OsisView`, `OsisInputConnection`). Each of the view's natives
//! is here; all run on the UI thread, where `shell::Shell` lives, but `nativeWake`'s post. The
//! store lives in the app's private files dir, made without a peer (desktop's `--peer`): pasting
//! an address into the search field adds one.
#![cfg(target_os = "android")]

mod gpu;
mod input;
mod shell;

use input::Motion;
use jni::objects::{JClass, JFloatArray, JIntArray, JObject, JString};
use jni::refs::Global;
use jni::sys::{jboolean, jfloat, jint, jlong};
use jni::{Env, JValue, jni_sig, jni_str};
#[allow(unused_imports, reason = "natives' glob import")]
use jni::{NativeMethod, native_method};
use ndk::native_window::NativeWindow;
use osis_app::store as app_store;
use osis_kit::ime::android;
use osis_kit::platform::Thresholds;
use std::time::Duration;
use osis_kit::render::Ui;
use osis_kit::store as data;
use osis_kit::window::Waker;
use shell::{Effect, Shell};
use std::cell::RefCell;
use std::sync::{Arc, Mutex};

type R<T> = jni::errors::Result<T>;

thread_local! {
    /// The UI, on the UI thread only.
    static SHELL: RefCell<Option<Shell>> = const { RefCell::new(None) };
}

/// The view, for the waker (any thread) and `nativeWake`.
static VIEW: Mutex<Option<Global<JObject<'static>>>> = Mutex::new(None);

/// Runs `f` on the shell, then the effects it left on the view (after the shell is released:
/// some call back into it).
fn with_shell<T>(env: &mut Env<'_>, view: &JObject<'_>, f: impl FnOnce(&mut Shell) -> T) -> Option<T> {
    let (r, fx) = SHELL.with(|c| match c.try_borrow_mut() {
        Ok(mut s) => match s.as_mut() {
            Some(sh) => {
                let r = f(sh);
                (Some(r), std::mem::take(&mut sh.fx))
            }
            None => (None, Vec::new()),
        },
        Err(_) => {
            log::error!("a view callback re-entered the shell");
            (None, Vec::new())
        }
    });
    for e in fx {
        if let Err(e) = effect(env, view, e) {
            log::warn!("view: {e}");
            // a Java exception left pending would fail every later JNI call and then throw from
            // this native into the view's caller
            if env.exception_check() {
                env.exception_describe();
                env.exception_clear();
            }
        }
    }
    r
}

fn effect(env: &mut Env<'_>, view: &JObject<'_>, e: Effect) -> R<()> {
    let call = |env: &mut Env<'_>, name, args: &[JValue]| -> R<()> {
        let sig = match args.len() {
            0 => jni_sig!(() -> void),
            _ => jni_sig!((a: jint, b: jint, c: jint, d: jint) -> void),
        };
        env.call_method(view, name, sig, args).map(drop)
    };
    match e {
        Effect::Frame => call(env, jni_str!("requestFrame"), &[]),
        Effect::ShowKeyboard => call(env, jni_str!("showKeyboard"), &[]),
        Effect::HideKeyboard => call(env, jni_str!("hideKeyboard"), &[]),
        Effect::Restart => call(env, jni_str!("restartInput"), &[]),
        Effect::Selection([a, b, c, d]) => call(env, jni_str!("updateSelection"), &[JValue::Int(a), JValue::Int(b), JValue::Int(c), JValue::Int(d)]),
        Effect::SetClipboard(s) => {
            let s = env.new_string(s)?;
            env.call_method(view, jni_str!("setClipboard"), jni_sig!((s: JString) -> void), &[JValue::Object(&s)]).map(drop)
        }
    }
}

/// Wakes the UI thread from any thread: `OsisView.wake` posts `nativeWake`.
fn wake_view() {
    let Ok(vm) = jni::JavaVM::singleton() else { return };
    let r = vm.attach_current_thread(|env| -> R<()> {
        let view = VIEW.lock().map_err(|_| jni::errors::Error::JniCall(jni::errors::JniError::Unknown))?;
        if let Some(v) = view.as_ref() {
            env.call_method(v, jni_str!("wake"), jni_sig!(() -> void), &[])?;
        }
        Ok(())
    });
    if let Err(e) = r {
        log::warn!("wake: {e}");
    }
}

// --- the view's natives

/// The exported `Java_net_osis_app_OsisView_*` functions, type-checked against java/'s
/// declarations by `native_method!`.
mod natives {
    #![allow(deprecated, reason = "jni 0.22's native_method! calls AtomicBool::fetch_update")]
    use super::*;

    const _: NativeMethod = native_method! { java_type = "net.osis.app.OsisView", extern fn native_create(dir: JString, density: jfloat, dark: jboolean, gestures: jint[]) };
    const _: NativeMethod = native_method! { java_type = "net.osis.app.OsisView", extern fn native_destroy() };
    const _: NativeMethod = native_method! { java_type = "net.osis.app.OsisView", static extern fn native_wake() };
    const _: NativeMethod = native_method! { java_type = "net.osis.app.OsisView", extern fn native_surface(surface: android.view.Surface, width: jint, height: jint) };
    const _: NativeMethod = native_method! { java_type = "net.osis.app.OsisView", extern fn native_surface_gone() };
    const _: NativeMethod = native_method! { java_type = "net.osis.app.OsisView", extern fn native_frame() };
    const _: NativeMethod = native_method! { java_type = "net.osis.app.OsisView", extern fn native_touch(action: jint, index: jint, ids: jint[], tools: jint[], xy: jfloat[], pressure: jfloat[], buttons: jint, meta: jint, time: jlong) -> jboolean };
    const _: NativeMethod = native_method! { java_type = "net.osis.app.OsisView", extern fn native_key(action: jint, key_code: jint, unicode: jint, meta: jint, repeat: jint) -> jboolean };
    const _: NativeMethod = native_method! { java_type = "net.osis.app.OsisView", extern fn native_focus(focused: jboolean) };
    const _: NativeMethod = native_method! { java_type = "net.osis.app.OsisView", extern fn native_insets(left: jint, top: jint, right: jint, bottom: jint) };
    const _: NativeMethod = native_method! { java_type = "net.osis.app.OsisView", extern fn native_config(density: jfloat, dark: jboolean) };
    const _: NativeMethod = native_method! { java_type = "net.osis.app.OsisView", extern fn native_back() -> jboolean };
    const _: NativeMethod = native_method! { java_type = "net.osis.app.OsisView", extern fn native_editing() -> jboolean };
    const _: NativeMethod = native_method! { java_type = "net.osis.app.OsisView", extern fn native_editor_info() -> jint[] };
    const _: NativeMethod = native_method! { java_type = "net.osis.app.OsisView", extern fn native_text() -> JString };
    const _: NativeMethod = native_method! { java_type = "net.osis.app.OsisView", extern fn native_offsets() -> jint[] };
    const _: NativeMethod = native_method! { java_type = "net.osis.app.OsisView", extern fn native_text_before(n: jint) -> JString };
    const _: NativeMethod = native_method! { java_type = "net.osis.app.OsisView", extern fn native_text_after(n: jint) -> JString };
    const _: NativeMethod = native_method! { java_type = "net.osis.app.OsisView", extern fn native_selected_text() -> JString };
    const _: NativeMethod = native_method! { java_type = "net.osis.app.OsisView", extern fn native_caps_mode(req_modes: jint) -> jint };
    const _: NativeMethod = native_method! { java_type = "net.osis.app.OsisView", extern fn native_replace_text(text: JString, new_cursor: jint, composing: jboolean) -> jboolean };
    const _: NativeMethod = native_method! { java_type = "net.osis.app.OsisView", extern fn native_set_composing_region(start: jint, end: jint) -> jboolean };
    const _: NativeMethod = native_method! { java_type = "net.osis.app.OsisView", extern fn native_finish_composing() -> jboolean };
    const _: NativeMethod = native_method! { java_type = "net.osis.app.OsisView", extern fn native_set_selection(start: jint, end: jint) -> jboolean };
    const _: NativeMethod = native_method! { java_type = "net.osis.app.OsisView", extern fn native_delete_surrounding(before: jint, after: jint, code_points: jboolean) -> jboolean };
    const _: NativeMethod = native_method! { java_type = "net.osis.app.OsisView", extern fn native_editor_action(action: jint) -> jboolean };
    const _: NativeMethod = native_method! { java_type = "net.osis.app.OsisView", extern fn native_shortcut(letter: JString) -> jboolean };
    const _: NativeMethod = native_method! { java_type = "net.osis.app.OsisView", extern fn native_batch(begin: jboolean) -> jboolean };
    const _: NativeMethod = native_method! { java_type = "net.osis.app.OsisView", extern fn native_close_connection() };
}

/// `gestures`: `ViewConfiguration`'s double-tap timeout (ms), double-tap slop (px), long-press
/// timeout (ms) and touch slop (px).
fn native_create<'l>(env: &mut Env<'l>, this: JObject<'l>, dir: JString<'l>, density: jfloat, dark: jboolean, gestures: JIntArray<'l>) -> R<()> {
    init_logging();
    *VIEW.lock().map_err(|_| jni::errors::Error::JniCall(jni::errors::JniError::Unknown))? = Some(env.new_global_ref(&this)?);
    let dir = std::path::PathBuf::from(dir.try_to_string(env)?).join("store");
    let mut g = [0; 4];
    gestures.get_region(env, 0, &mut g)?;
    let (ms, px) = (|i: jint| Duration::from_millis(u64::try_from(i).unwrap_or(0)), |i: jint| f64::from(i) / f64::from(density).max(0.1));
    let thresholds = Thresholds { double_tap: ms(g[0]), double_tap_slop: px(g[1]), long_press: ms(g[2]), touch_slop: px(g[3]) };
    match open(&dir) {
        Ok(ui) => {
            let sh = Shell::new(ui, f64::from(density), dark, thresholds);
            SHELL.with(|c| *c.borrow_mut() = Some(sh));
            with_shell(env, &this, |_| ());
        }
        Err(e) => log::error!("osis-app: {e}"),
    }
    Ok(())
}

fn open(dir: &std::path::Path) -> Result<Ui, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let waker = Waker::new(wake_view);
    let w = waker.clone();
    let db = data::open(dir, Vec::new(), Arc::new(move || w.wake())).map_err(|e| format!("{}: {e}", dir.display()))?;
    let data = app_store::data(db);
    data.main_group().map_err(|e| e.to_string())?;
    Ui::new(data, waker).map_err(|e| e.to_string())
}

fn native_destroy<'l>(_env: &mut Env<'l>, _this: JObject<'l>) -> R<()> {
    // drop the UI (and close the store) before forgetting the view its waker calls
    drop(SHELL.with(|c| c.borrow_mut().take()));
    if let Ok(mut v) = VIEW.lock() {
        *v = None;
    }
    Ok(())
}

fn native_wake<'l>(env: &mut Env<'l>, _class: JClass<'l>) -> R<()> {
    let view = VIEW.lock().ok().and_then(|v| v.as_ref().map(|g| env.new_local_ref(g))).transpose()?;
    if let Some(view) = view {
        with_shell(env, &view, Shell::wake);
    }
    Ok(())
}

#[allow(unsafe_code, reason = "the NDK makes a native window of a Surface only through a raw JNI call")]
fn native_window(env: &Env<'_>, surface: &JObject<'_>) -> Option<NativeWindow> {
    // SAFETY: `env` is this thread's JNI environment, live for this native call, and `surface` a
    // live local reference to the android.view.Surface the view's holder passed in.
    unsafe { NativeWindow::from_surface(env.get_raw().cast(), surface.as_raw().cast()) }
}

fn native_surface<'l>(env: &mut Env<'l>, this: JObject<'l>, surface: JObject<'l>, width: jint, height: jint) -> R<()> {
    let Some(window) = native_window(env, &surface) else {
        log::error!("no native window for the surface");
        return Ok(());
    };
    let size = |i: jint| u32::try_from(i).unwrap_or(0);
    with_shell(env, &this, |s| s.surface(window, size(width), size(height)));
    Ok(())
}

fn native_surface_gone<'l>(env: &mut Env<'l>, this: JObject<'l>) -> R<()> {
    with_shell(env, &this, Shell::surface_gone);
    Ok(())
}

fn native_frame<'l>(env: &mut Env<'l>, this: JObject<'l>) -> R<()> {
    with_shell(env, &this, Shell::frame);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn native_touch<'l>(env: &mut Env<'l>, this: JObject<'l>, action: jint, index: jint, ids: JIntArray<'l>, tools: JIntArray<'l>, xy: JFloatArray<'l>, pressure: JFloatArray<'l>, _buttons: jint, meta: jint, time: jlong) -> R<jboolean> {
    let ints = |env: &mut Env<'l>, a: &JIntArray<'l>| -> R<Vec<jint>> {
        let mut v = vec![0; a.len(env)?];
        a.get_region(env, 0, &mut v)?;
        Ok(v)
    };
    let floats = |env: &mut Env<'l>, a: &JFloatArray<'l>| -> R<Vec<jfloat>> {
        let mut v = vec![0.0; a.len(env)?];
        a.get_region(env, 0, &mut v)?;
        Ok(v)
    };
    let (ids, tools, xy, pressure) = (ints(env, &ids)?, ints(env, &tools)?, floats(env, &xy)?, floats(env, &pressure)?);
    let m = Motion { action, index: usize::try_from(index).unwrap_or(0), ids: &ids, tools: &tools, xy: &xy, pressure: &pressure, meta, time_ms: time };
    Ok(with_shell(env, &this, |s| s.touch(&m)).unwrap_or(false))
}

fn native_key<'l>(env: &mut Env<'l>, this: JObject<'l>, action: jint, key_code: jint, unicode: jint, meta: jint, repeat: jint) -> R<jboolean> {
    Ok(with_shell(env, &this, |s| s.key(action, key_code, unicode, meta, repeat)).unwrap_or(false))
}

fn native_focus<'l>(env: &mut Env<'l>, this: JObject<'l>, focused: jboolean) -> R<()> {
    with_shell(env, &this, |s| s.focus(focused));
    Ok(())
}

fn native_insets<'l>(env: &mut Env<'l>, this: JObject<'l>, left: jint, top: jint, right: jint, bottom: jint) -> R<()> {
    with_shell(env, &this, |s| s.insets([left, top, right, bottom].map(f64::from)));
    Ok(())
}

fn native_config<'l>(env: &mut Env<'l>, this: JObject<'l>, density: jfloat, dark: jboolean) -> R<()> {
    with_shell(env, &this, |s| s.config(f64::from(density), dark));
    Ok(())
}

fn native_back<'l>(env: &mut Env<'l>, this: JObject<'l>) -> R<jboolean> {
    Ok(with_shell(env, &this, Shell::back).unwrap_or(false))
}

fn native_editing<'l>(env: &mut Env<'l>, this: JObject<'l>) -> R<jboolean> {
    Ok(with_shell(env, &this, |s| s.editing()).unwrap_or(false))
}

fn int_array<'l>(env: &mut Env<'l>, v: &[jint]) -> R<JIntArray<'l>> {
    let a = JIntArray::new(env, v.len())?;
    a.set_region(env, 0, v)?;
    Ok(a)
}

fn string<'l>(env: &mut Env<'l>, s: Option<String>) -> R<JString<'l>> {
    match s {
        Some(s) => env.new_string(s),
        None => Ok(JString::null()),
    }
}

fn native_editor_info<'l>(env: &mut Env<'l>, this: JObject<'l>) -> R<JIntArray<'l>> {
    match with_shell(env, &this, Shell::editor_info).flatten() {
        Some(info) => int_array(env, &info),
        None => Ok(JIntArray::null()),
    }
}

fn native_text<'l>(env: &mut Env<'l>, this: JObject<'l>) -> R<JString<'l>> {
    let s = with_shell(env, &this, |s| s.text()).flatten();
    string(env, Some(s.unwrap_or_default()))
}

fn native_offsets<'l>(env: &mut Env<'l>, this: JObject<'l>) -> R<JIntArray<'l>> {
    let o = with_shell(env, &this, |s| s.offsets()).unwrap_or([0, 0, -1, -1]);
    int_array(env, &o)
}

fn native_text_before<'l>(env: &mut Env<'l>, this: JObject<'l>, n: jint) -> R<JString<'l>> {
    let s = with_shell(env, &this, |s| s.text_before(n)).flatten();
    string(env, s)
}

fn native_text_after<'l>(env: &mut Env<'l>, this: JObject<'l>, n: jint) -> R<JString<'l>> {
    let s = with_shell(env, &this, |s| s.text_after(n)).flatten();
    string(env, s)
}

fn native_selected_text<'l>(env: &mut Env<'l>, this: JObject<'l>) -> R<JString<'l>> {
    let s = with_shell(env, &this, |s| s.selected_text()).flatten();
    string(env, s)
}

fn native_caps_mode<'l>(env: &mut Env<'l>, this: JObject<'l>, req_modes: jint) -> R<jint> {
    Ok(with_shell(env, &this, |s| s.caps_mode(req_modes)).unwrap_or(0))
}

/// Runs an input-connection edit; false when no field has the keyboard (the connection is stale).
fn edit<'l>(env: &mut Env<'l>, this: &JObject<'l>, f: impl FnOnce(&dyn osis_kit::masonry::core::ImeText) -> Option<osis_kit::masonry::core::TextEdit>) -> R<jboolean> {
    Ok(with_shell(env, this, |s| s.edit(f)).unwrap_or(false))
}

fn native_replace_text<'l>(env: &mut Env<'l>, this: JObject<'l>, text: JString<'l>, new_cursor: jint, composing: jboolean) -> R<jboolean> {
    let text = text.try_to_string(env)?;
    edit(env, &this, |t| Some(android::replace_text(t, &text, new_cursor, composing)))
}

fn native_set_composing_region<'l>(env: &mut Env<'l>, this: JObject<'l>, start: jint, end: jint) -> R<jboolean> {
    edit(env, &this, |t| Some(android::set_composing_region(t, start, end)))
}

fn native_finish_composing<'l>(env: &mut Env<'l>, this: JObject<'l>) -> R<jboolean> {
    edit(env, &this, android::finish_composing)
}

fn native_set_selection<'l>(env: &mut Env<'l>, this: JObject<'l>, start: jint, end: jint) -> R<jboolean> {
    edit(env, &this, |t| android::set_selection(t, start, end))
}

fn native_delete_surrounding<'l>(env: &mut Env<'l>, this: JObject<'l>, before: jint, after: jint, code_points: jboolean) -> R<jboolean> {
    edit(env, &this, |t| android::delete_surrounding(t, before, after, code_points))
}

fn native_editor_action<'l>(env: &mut Env<'l>, this: JObject<'l>, _action: jint) -> R<jboolean> {
    Ok(with_shell(env, &this, Shell::editor_action).unwrap_or(false))
}

fn native_shortcut<'l>(env: &mut Env<'l>, this: JObject<'l>, letter: JString<'l>) -> R<jboolean> {
    let letter = letter.try_to_string(env)?;
    Ok(with_shell(env, &this, |s| s.shortcut(&letter)).unwrap_or(false))
}

fn native_batch<'l>(env: &mut Env<'l>, this: JObject<'l>, begin: jboolean) -> R<jboolean> {
    Ok(with_shell(env, &this, |s| s.batch(begin)).unwrap_or(false))
}

fn native_close_connection<'l>(env: &mut Env<'l>, this: JObject<'l>) -> R<()> {
    with_shell(env, &this, Shell::close_connection);
    Ok(())
}

// --- logging and the clipboard

fn init_logging() {
    android_logger::init_once(android_logger::Config::default().with_max_level(log::LevelFilter::Info).with_tag("osis"));
    std::panic::set_hook(Box::new(|p| log::error!("panic: {p}")));
    // before masonry's default subscriber (stderr, and a log file in the unwritable temp_dir)
    let _ = tracing_subscriber::fmt().with_writer(|| Logcat(Vec::new())).with_ansi(false).without_time().with_max_level(tracing::Level::INFO).try_init();
}

/// Writes each formatted tracing event to logcat.
struct Logcat(Vec<u8>);

impl std::io::Write for Logcat {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for Logcat {
    fn drop(&mut self) {
        log::info!("{}", String::from_utf8_lossy(&self.0).trim_end());
    }
}

/// The primary clip as text (any thread): `ClipboardManager.getPrimaryClip().getItemAt(0).coerceToText()`.
pub(crate) fn clipboard() -> Option<String> {
    let vm = jni::JavaVM::singleton().ok()?;
    let r = vm.attach_current_thread(|env| -> R<Option<String>> {
        let ctx = env.call_static_method(jni_str!("android/app/ActivityThread"), jni_str!("currentApplication"), jni_sig!("()Landroid/app/Application;"), &[])?.l()?;
        let name = env.new_string("clipboard")?;
        let cm = env.call_method(&ctx, jni_str!("getSystemService"), jni_sig!("(Ljava/lang/String;)Ljava/lang/Object;"), &[JValue::Object(&name)])?.l()?;
        let clip = env.call_method(&cm, jni_str!("getPrimaryClip"), jni_sig!("()Landroid/content/ClipData;"), &[])?.l()?;
        if clip.is_null() || env.call_method(&clip, jni_str!("getItemCount"), jni_sig!("()I"), &[])?.i()? == 0 {
            return Ok(None);
        }
        let item = env.call_method(&clip, jni_str!("getItemAt"), jni_sig!("(I)Landroid/content/ClipData$Item;"), &[JValue::Int(0)])?.l()?;
        let text = env.call_method(&item, jni_str!("coerceToText"), jni_sig!("(Landroid/content/Context;)Ljava/lang/CharSequence;"), &[JValue::Object(&ctx)])?.l()?;
        if text.is_null() {
            return Ok(None);
        }
        let s = env.call_method(&text, jni_str!("toString"), jni_sig!("()Ljava/lang/String;"), &[])?.l()?;
        Ok(Some(env.cast_local::<JString>(s)?.try_to_string(env)?))
    });
    r.unwrap_or_else(|e| {
        log::warn!("clipboard: {e}");
        None
    })
}
