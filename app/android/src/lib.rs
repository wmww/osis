//! The osis app on Android (experimental; notes/android.md): the same app as desktop, opened by
//! NativeActivity through `android_main`. The store lives in the app's private files dir, made
//! without a peer (desktop's `--peer`): the paste chip beside the search field adds one. The system clipboard
//! backs the app's paste chips (no soft-keyboard text yet).
#![cfg(target_os = "android")]

use jni::objects::JString;
use jni::{JValue, jni_sig, jni_str};
use osis_app::store as app_store;
use osis_kit::render::{Msg, Ui, tree};
use osis_kit::store as data;
use osis_kit::marshal::mailbox;
use osis_kit::masonry_winit::app::EventLoop;
use osis_kit::window::App;
use winit::platform::android::EventLoopBuilderExtAndroid;
use winit::platform::android::activity::AndroidApp;

#[allow(unsafe_code, reason = "NativeActivity finds the entry point by its unmangled name")]
#[unsafe(no_mangle)]
fn android_main(app: AndroidApp) {
    android_logger::init_once(android_logger::Config::default().with_max_level(log::LevelFilter::Info).with_tag("osis"));
    std::panic::set_hook(Box::new(|p| log::error!("panic: {p}")));
    // before masonry's default subscriber (stderr, and a log file in the unwritable temp_dir)
    let _ = tracing_subscriber::fmt().with_writer(|| Logcat(Vec::new())).with_ansi(false).without_time().with_max_level(tracing::Level::INFO).try_init();
    osis_kit::platform::set_clipboard(clipboard);
    if let Err(e) = run(app) {
        log::error!("osis-app: {e}");
    }
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

fn run(app: AndroidApp) -> Result<(), String> {
    let dir = app.internal_data_path().ok_or("no files dir")?.join("store");
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let db = data::open(&dir, Vec::new()).map_err(|e| format!("{}: {e}", dir.display()))?;
    let data = app_store::data(db);
    data.main_group().map_err(|e| e.to_string())?;
    let event_loop = EventLoop::with_user_event().with_android_app(app).build().map_err(|e| e.to_string())?;
    let app = App::with_event_loop(event_loop);
    let (mb, inbox) = mailbox::<Msg>(app.waker());
    let ui = Ui::new(data, app.window(), mb, inbox).map_err(|e| e.to_string())?;
    let look = ui.look();
    let root = tree(look.clone());
    app.run("osis", (400.0, 800.0), root, ui, look.bg).map_err(|e| e.to_string())
}

/// The primary clip as text: `ClipboardManager.getPrimaryClip().getItemAt(0).coerceToText()`.
fn clipboard() -> Option<String> {
    let vm = jni::JavaVM::singleton().ok()?;
    let r = vm.attach_current_thread(|env| -> jni::errors::Result<Option<String>> {
        let ctx = env.call_static_method(jni_str!("android/app/ActivityThread"), jni_str!("currentApplication"), jni_sig!("()Landroid/app/Application;"), &[])?.l()?;
        let name = env.new_string("clipboard")?;
        let cm = env.call_method(&ctx, jni_str!("getSystemService"), jni_sig!("(Ljava/lang/String;)Ljava/lang/Object;"), &[JValue::Object(&name)])?.l()?;
        let clip = env.call_method(&cm, jni_str!("getPrimaryClip"), jni_sig!("()Landroid/content/ClipData;"), &[])?.l()?;
        if clip.is_null() {
            return Ok(None);
        }
        let item = env.call_method(&clip, jni_str!("getItemAt"), jni_sig!("(I)Landroid/content/ClipData$Item;"), &[JValue::Int(0)])?.l()?;
        let text = env.call_method(&item, jni_str!("coerceToText"), jni_sig!("(Landroid/content/Context;)Ljava/lang/CharSequence;"), &[JValue::Object(&ctx)])?.l()?;
        let s = env.call_method(&text, jni_str!("toString"), jni_sig!("()Ljava/lang/String;"), &[])?.l()?;
        Ok(Some(env.cast_local::<JString>(s)?.try_to_string(env)?))
    });
    r.unwrap_or_else(|e| {
        log::warn!("clipboard: {e}");
        None
    })
}
