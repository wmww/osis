//! Starting over a store that cannot open (as every shell does, through `Start`): the window says
//! why, with the error; start fresh moves the store aside, keeping it on disk, and opens a new one.
use crate::view_tree::Small;
use osis_kit::masonry::app::{RenderRoot, RenderRootOptions, RenderRootSignal, WindowSizePolicy};
use osis_kit::masonry::core::{PointerButton, PointerButtonEvent, PointerEvent, PointerId, PointerInfo, PointerState, PointerType, Widget, WidgetId, WidgetRef, WindowEvent};
use osis_kit::masonry::dpi::{PhysicalPosition, PhysicalSize};
use osis_kit::masonry::widgets::{Label, TextArea};
use osis_kit::render::{Start, Started, tree};
use osis_kit::store::{Data, Registry};
use osis_kit::widgets::Chip;
use osis_kit::window::Waker;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, channel};

struct Window {
    ui: Started,
    rr: RenderRoot,
    signals: Receiver<RenderRootSignal>,
}

impl Window {
    fn open(dir: &Path) -> Window {
        Window::open_with(dir, Box::new(|db| Ok(Data::new(db, Arc::new(Small::default()), Registry::kit()))))
    }

    fn open_with(dir: &Path, data: Box<dyn Fn(osis::Osis) -> Result<Data, String>>) -> Window {
        let mut ui = Start { dir: dir.to_path_buf(), dial: Vec::new(), waker: Waker::new(|| {}), data }.open();
        let opts = RenderRootOptions {
            default_properties: Arc::new(osis_kit::masonry::theme::default_property_set()),
            use_system_fonts: false,
            size_policy: WindowSizePolicy::User,
            size: PhysicalSize::new(800, 700),
            scale_factor: 1.0,
            test_font: None,
        };
        let (tx, signals) = channel();
        let mut rr = RenderRoot::new(tree(ui.look()), move |s| drop(tx.send(s)), opts);
        ui.start(&mut rr, Box::new(crate::input::Recorder::default()), 1.0, false);
        ui.wake(&mut rr);
        Window { ui, rr, signals }
    }

    /// The text on screen: every label and text area, and what a screen reader is told.
    fn texts(&mut self) -> Vec<String> {
        fn walk(w: WidgetRef<'_, dyn Widget>, out: &mut Vec<String>) {
            if let Some(l) = w.downcast::<Label>() {
                out.push(l.inner().text().to_string());
            } else if let Some(t) = w.downcast::<TextArea<false>>() {
                out.push(t.inner().text().to_string());
            }
            for c in w.children() {
                walk(c, out);
            }
        }
        self.rr.handle_window_event(WindowEvent::EnableAccessTree);
        let (_, update) = self.rr.redraw();
        let mut out: Vec<String> = update.unwrap().nodes.iter().filter_map(|(_, n)| n.label().map(str::to_string)).collect();
        walk(self.rr.get_layer_root(0), &mut out);
        out
    }

    fn shows(&mut self, text: &str) -> bool {
        self.texts().iter().any(|l| l.contains(text))
    }

    /// The one button on screen (start fresh), if any.
    fn button(&self) -> Option<WidgetId> {
        fn find(w: WidgetRef<'_, dyn Widget>) -> Option<WidgetId> {
            if w.downcast::<Chip>().is_some() {
                return Some(w.id());
            }
            w.children().into_iter().find_map(find)
        }
        find(self.rr.get_layer_root(0))
    }

    /// A click on `id`, its actions handed to the UI as a shell does.
    fn click(&mut self, id: WidgetId) {
        let _ = self.rr.redraw();
        let c = self.rr.get_widget(id).unwrap().ctx().bounding_rect().center();
        let pointer = PointerInfo { pointer_id: Some(PointerId::PRIMARY), persistent_device_id: None, pointer_type: PointerType::Mouse };
        let state = PointerState { time: 1, position: PhysicalPosition::new(c.x, c.y), count: 1, scale_factor: 1.0, ..Default::default() };
        let ev = |state| PointerButtonEvent { button: Some(PointerButton::Primary), pointer, state };
        self.ui.pointer(&mut self.rr, PointerEvent::Down(ev(state.clone())));
        self.ui.pointer(&mut self.rr, PointerEvent::Up(ev(PointerState { time: 2, ..state })));
        for s in self.signals.try_iter().collect::<Vec<_>>() {
            if let RenderRootSignal::Action(a, id) = s {
                self.ui.action(&mut self.rr, id, a);
            }
        }
    }
}

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("osis-kit-start-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A store whose database is garbage shows the error screen, naming the store and where start
/// fresh puts it; start fresh moves it there untouched and opens a working, empty store.
#[test]
fn a_store_that_cannot_open_shows_why_and_starts_fresh() {
    let base = scratch("garbage");
    let dir = base.join("store");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("db.redb"), b"not a database").unwrap();
    let mut w = Window::open(&dir);
    assert!(w.ui.error().is_some_and(|e| e.contains(&dir.display().to_string())), "{:?}", w.ui.error());
    assert!(w.shows("The store could not be opened"));
    assert!(w.shows(w.ui.error().unwrap().to_string().as_str()), "the error text is on screen");
    let aside = base.join("store.old");
    assert!(w.shows(&aside.display().to_string()), "says where the old store goes");
    let fresh = w.button().expect("start fresh");
    w.click(fresh);
    assert_eq!(w.ui.error(), None);
    assert!(!w.shows("could not be opened"));
    assert!(w.shows("Search"), "the app's home shows");
    assert_eq!(std::fs::read(aside.join("db.redb")).unwrap(), b"not a database", "the old store is kept as it was");
    // the new store works: closed, it opens again
    assert!(matches!(w.ui.close(), Ok(osis::Close::Closed)));
    let mut w = Window::open(&dir);
    assert_eq!(w.ui.error(), None);
    assert!(w.shows("Search"));
    drop(w);
    let _ = std::fs::remove_dir_all(&base);
}

/// A file where the store's dir should be: start fresh never overwrites the name it showed when
/// that was taken since, but names the next free one; with nothing at the path there is nothing
/// to move and no button.
#[test]
fn start_fresh_takes_a_free_name_and_needs_something_to_move() {
    let base = scratch("file");
    let dir = base.join("store");
    std::fs::write(&dir, b"a file").unwrap();
    let mut w = Window::open(&dir);
    assert!(w.ui.error().is_some());
    assert!(w.shows(&base.join("store.old").display().to_string()));
    std::fs::write(base.join("store.old"), b"taken since").unwrap();
    let fresh = w.button().expect("start fresh");
    w.click(fresh);
    assert_eq!(std::fs::read(base.join("store.old")).unwrap(), b"taken since", "never overwritten");
    assert_eq!(std::fs::read(&dir).unwrap(), b"a file", "not moved yet");
    assert!(w.shows(&base.join("store.old-2").display().to_string()), "names the next free one");
    let fresh = w.button().expect("start fresh");
    w.click(fresh);
    assert_eq!(w.ui.error(), None);
    assert_eq!(std::fs::read(base.join("store.old-2")).unwrap(), b"a file");
    assert!(dir.join("db.redb").exists());
    drop(w);
    // under a file nothing can be made, and nothing is there to move
    let mut w = Window::open(&base.join("store.old-2").join("store"));
    assert!(w.shows("The store could not be opened"));
    assert_eq!(w.button(), None);
    drop(w);
    let _ = std::fs::remove_dir_all(&base);
}

/// Start fresh is only for a store that cannot be read: a store open elsewhere says so and offers
/// nothing, and so does a later step failing (the app's data setup), which leaves the store free.
#[test]
fn a_healthy_store_is_never_offered_start_fresh() {
    let base = scratch("healthy");
    let dir = base.join("store");
    let held = osis_kit::store::open(&dir, Vec::new(), Arc::new(|| {})).unwrap();
    let w = Window::open(&dir);
    assert!(w.ui.error().is_some_and(|e| e.contains("in use") && e.contains(dir.to_str().unwrap())), "{:?}", w.ui.error());
    assert_eq!(w.button(), None, "in use: no start fresh");
    drop(w);
    assert!(matches!(held.close(), Ok(osis::Close::Closed)));
    let w = Window::open_with(&dir, Box::new(|_| Err("no such theme".to_string())));
    assert_eq!(w.ui.error(), Some("no such theme"));
    assert_eq!(w.button(), None, "a later step: no start fresh");
    drop(w);
    let mut w = Window::open(&dir);
    assert_eq!(w.ui.error(), None, "the failed start closed the store");
    assert!(w.shows("Search"));
    drop(w);
    let _ = std::fs::remove_dir_all(&base);
}
