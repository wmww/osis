//! Starting the UI, the same on every shell: make the store dir, open the store in it, the app's
//! `Data` over it, its main group, then `Ui`. A failure shows why instead, in the app's look. Where
//! the store itself cannot be read (before stability, data an older build wrote may not load) it
//! offers one way on: start fresh, which moves the store aside to a sibling path (kept, never
//! deleted), says where, and opens a new one in its place. A store in use elsewhere, a later step
//! failing, or nothing at the path to move: no action.

use super::{Host, ROOT, Ui};
use crate::masonry::app::RenderRoot;
use crate::masonry::core::{ErasedAction, Handled, NewWidget, PointerEvent, Properties, TextCommand, TextEvent, Widget, WidgetId};
use crate::masonry::peniko::Color;
use crate::masonry::properties::Padding;
use crate::masonry::properties::types::{CrossAxisAlignment, Length};
use crate::masonry::widgets::Flex;
use crate::platform::Platform;
use crate::store::Data;
use crate::theme::{Look, Theme};
use crate::widgets::style::{self, Text};
use crate::icons::Icon;
use crate::widgets::{Chip, ChipMark, ChipPress, Frame, Page, Panel, PanelKind, Root};
use crate::window::Waker;
use osis::{Address, Osis};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// What a shell starts the UI with: the store's dir (made if missing), the nodes it dials
/// (`Config::dial`), the shell's waker, and the app's `Data` over an
/// opened store (an error shows on the failure screen).
pub struct Start {
    pub dir: PathBuf,
    pub dial: Vec<Address>,
    pub waker: Waker,
    pub data: Box<dyn Fn(Osis) -> Result<Data, String>>,
}

impl Start {
    /// The UI over the store in `dir`, or the screen saying why it could not open.
    pub fn open(self) -> Started {
        Started(match self.ui() {
            Ok(ui) => Shown::Ui(Box::new(ui)),
            Err(e) => Shown::Failed(Box::new(Failed::new(e, self, Host::default()))),
        })
    }

    fn ui(&self) -> Result<Ui, Failure> {
        let unreadable = |error| Failure { error, fresh: true };
        std::fs::create_dir_all(&self.dir).map_err(|e| unreadable(format!("{}: {e}", self.dir.display())))?;
        let w = self.waker.clone();
        // the store's own errors name it; `InUse` carries nothing, so it is named here
        let db = crate::store::open(&self.dir, self.dial.clone(), Arc::new(move || w.wake())).map_err(|e| match e {
            osis::Error::InUse => Failure { error: format!("{}: {e}", self.dir.display()), fresh: false },
            e => unreadable(e.to_string()),
        })?;
        let later = || -> Result<Ui, String> {
            let data = (self.data)(db.clone())?;
            data.main_group().map_err(|e| e.to_string())?;
            Ui::new(data, self.waker.clone()).map_err(|e| e.to_string())
        };
        // the store is fine: closed, so trying again (a restart) finds it free
        later().map_err(|error| {
            let _ = db.close();
            Failure { error, fresh: false }
        })
    }
}

/// Why the UI did not start, and whether start fresh is offered: only where the store itself
/// cannot be read.
struct Failure {
    error: String,
    fresh: bool,
}

/// What a shell started: the UI over its store, or the screen saying why the store could not
/// open. The shell hosts it on the UI thread; the calls needing only the platform go to `Host`,
/// whichever shows.
pub struct Started(Shown);

enum Shown {
    Ui(Box<Ui>),
    Failed(Box<Failed>),
}

struct Failed {
    /// What start fresh tries again.
    start: Start,
    host: Host,
    error: String,
    /// Where start fresh moves the store; `None`: not offered, or nothing is there to move.
    aside: Option<PathBuf>,
    look: Arc<Look>,
    /// The start fresh button, once shown.
    fresh: Option<WidgetId>,
}

impl Failed {
    fn new(f: Failure, start: Start, host: Host) -> Failed {
        let aside = aside(&start.dir).filter(|_| f.fresh);
        Failed { start, host, error: f.error, aside, look: Arc::new(Look::new(&Theme::named(None), false, None)), fresh: None }
    }

    /// Shows the failure screen under the root, in the default theme.
    fn show(&mut self, rr: &mut RenderRoot) {
        self.look = Arc::new(Look::new(&Theme::named(None), self.host.dark, None));
        let look = self.look.clone();
        let mut col = Flex::column().cross_axis_alignment(CrossAxisAlignment::Fill).with_gap(Length::px(look.sp(18.0)));
        col = col.with_child(style::heading(&look, "osis", Text::Brand)).with_child(style::prose(&look, "The store could not be opened", Text::Title));
        let error = NewWidget::new(Panel::new(style::prose(&look, &self.error, Text::Body), look.clone(), PanelKind::Inset, (12.0, 14.0)));
        col = col.with_child(error);
        self.fresh = None;
        if let Some(to) = &self.aside {
            let says = format!("Start fresh keeps it, moved to {}, and opens a new, empty store in its place.", to.display());
            let chip = NewWidget::new(Chip::new("Start fresh", None, ChipMark::Icon(Icon::Plus), look.clone()));
            self.fresh = Some(chip.id());
            col = col.with_child(style::prose(&look, &says, Text::Muted)).with_child(NewWidget::new(Flex::row().with_child(chip)));
        }
        let col = NewWidget::new_with_props(col, Properties::new().with(Padding::from_vh(look.sp(48.0), look.sp(16.0))));
        let w: NewWidget<dyn Widget> = NewWidget::new(Page::new(col, look.clone())).erased();
        rr.edit_widget_with_tag(ROOT, |mut r| {
            Root::set_look(&mut r, look, 0);
            Root::set_child(&mut r, w);
        });
    }
}

/// The first free sibling of `dir` named after it (`store.old`, then `store.old-2`, ...); `None`
/// when nothing is at `dir` or it has no name.
fn aside(dir: &Path) -> Option<PathBuf> {
    dir.symlink_metadata().ok()?;
    let dir = std::path::absolute(dir).ok()?;
    let name = dir.file_name()?.to_string_lossy().into_owned();
    (1u64..).map(|n| dir.with_file_name(if n == 1 { format!("{name}.old") } else { format!("{name}.old-{n}") })).find(|p| p.symlink_metadata().is_err())
}

/// Moves `from` to `to`, never replacing what is there: a dir's rename replaces at most an empty
/// dir (POSIX); anything else is linked at `to` (failing when taken), then unlinked at `from`.
fn move_aside(from: &Path, to: &Path) -> std::io::Result<()> {
    if from.symlink_metadata()?.is_dir() {
        std::fs::rename(from, to)
    } else {
        std::fs::hard_link(from, to)?;
        std::fs::remove_file(from)
    }
}

/// A UI made by hand (tests): no failure screen to fall back to.
impl From<Ui> for Started {
    fn from(ui: Ui) -> Started {
        Started(Shown::Ui(Box::new(ui)))
    }
}

impl Started {
    /// Why the store could not open, while the failure screen shows.
    pub fn error(&self) -> Option<&str> {
        match &self.0 {
            Shown::Failed(f) => Some(&f.error),
            Shown::Ui(_) => None,
        }
    }

    /// Drops the UI and closes its store, returning once it can be opened again (dropping alone
    /// leaves it locked until the node's runtime has shut down). `StillOpen` while something
    /// else holds a handle.
    pub fn close(self) -> osis::Result<osis::Close> {
        match self.0 {
            Shown::Ui(ui) => {
                let db = ui.data.db.clone();
                drop(ui);
                db.close()
            }
            Shown::Failed(_) => Ok(osis::Close::Closed),
        }
    }

    /// Start fresh: the store goes aside (to the path the screen named, unless that was taken
    /// since: then the screen names the next free one) and a new one opens in its place, handed
    /// what the shell has told so far.
    fn start_fresh(&mut self, rr: &mut RenderRoot) {
        let Shown::Failed(f) = &mut self.0 else { return };
        let Some(to) = f.aside.clone() else { return };
        if let Err(e) = move_aside(&f.start.dir, &to) {
            match e.kind() {
                std::io::ErrorKind::AlreadyExists | std::io::ErrorKind::DirectoryNotEmpty => f.aside = aside(&f.start.dir),
                _ => f.error = format!("could not move {} to {}: {e}", f.start.dir.display(), to.display()),
            }
            return f.show(rr);
        }
        match f.start.ui() {
            Ok(mut ui) => {
                let mut host = std::mem::take(&mut f.host);
                let platform = host.attached.take().map(|a| a.platform);
                ui.host = host;
                if let Some(p) = platform {
                    ui.attach(p);
                }
                ui.host.resized(rr, ui.host.scale, ui.host.insets);
                ui.wake(rr);
                self.0 = Shown::Ui(Box::new(ui));
            }
            Err(e) => {
                (f.error, f.aside) = (e.error, aside(&f.start.dir).filter(|_| e.fresh));
                f.show(rr);
            }
        }
    }

    fn host(&mut self) -> &mut Host {
        match &mut self.0 {
            Shown::Ui(ui) => &mut ui.host,
            Shown::Failed(f) => &mut f.host,
        }
    }
}

/// `Ui`'s shell calls (render/mod.rs), each passed on to it or answered by the failure screen.
impl Started {
    /// The first look, for the initial root widget.
    pub fn look(&self) -> Arc<Look> {
        match &self.0 {
            Shown::Ui(ui) => ui.look(),
            Shown::Failed(f) => f.look.clone(),
        }
    }

    /// The window exists: register the fonts, take the platform, show the screen. `scale` is
    /// physical pixels per logical pixel, `dark` the system's dark mode.
    pub fn start(&mut self, rr: &mut RenderRoot, platform: Box<dyn Platform>, scale: f64, dark: bool) {
        match &mut self.0 {
            Shown::Ui(ui) => ui.start(rr, platform, scale, dark),
            Shown::Failed(f) => {
                crate::fonts::register(rr);
                (f.host.scale, f.host.dark) = (scale, dark);
                // no long press here: nothing on the failure screen has a meaning for one
                f.host.attach(platform, Box::new(|_, _| {}), f.look.clone());
                f.show(rr);
            }
        }
    }

    /// The window's size or scale changed.
    pub fn resized(&mut self, rr: &mut RenderRoot, scale: f64) {
        let insets = self.host().insets;
        self.resize(rr, scale, insets);
    }

    /// What covers the window's edges changed (physical pixels: left, top, right, bottom): the
    /// screen is laid out clear of it, and the width that leaves is what the layout follows.
    pub fn set_insets(&mut self, rr: &mut RenderRoot, insets: [f64; 4]) {
        let scale = self.host().scale;
        self.resize(rr, scale, insets);
    }

    fn resize(&mut self, rr: &mut RenderRoot, scale: f64, insets: [f64; 4]) {
        match &mut self.0 {
            Shown::Ui(ui) => ui.resized(rr, scale, insets),
            Shown::Failed(f) => f.host.resized(rr, scale, insets),
        }
    }

    /// The system's dark mode changed.
    pub fn theme_changed(&mut self, rr: &mut RenderRoot, dark: bool) {
        match &mut self.0 {
            Shown::Ui(ui) => ui.theme_changed(rr, dark),
            Shown::Failed(f) => {
                f.host.dark = dark;
                f.show(rr);
            }
        }
    }

    /// The system's Back; false when there is nowhere to go back to, so the system handles it.
    pub fn back(&mut self, rr: &mut RenderRoot) -> bool {
        match &mut self.0 {
            Shown::Ui(ui) => ui.back(rr),
            Shown::Failed(_) => false,
        }
    }

    pub fn pointer(&mut self, rr: &mut RenderRoot, e: PointerEvent) {
        self.host().pointer(rr, e);
    }

    pub fn text_event(&mut self, rr: &mut RenderRoot, e: TextEvent) -> Handled {
        self.host().text_event(rr, e)
    }

    pub fn menu_pick(&mut self, rr: &mut RenderRoot, c: TextCommand) {
        self.host().menu_pick(rr, c);
    }

    pub fn menu_gone(&mut self) {
        self.host().menu_gone();
    }

    pub fn text_focus(&mut self, rr: &mut RenderRoot) {
        self.host().text_focus(rr);
    }

    pub fn paste(&mut self, rr: &mut RenderRoot) {
        self.host().paste(rr);
    }

    pub fn copy(&mut self, text: String) {
        self.host().copy(text);
    }

    /// The colour under everything, for the shell to clear with.
    pub fn base_color(&self) -> Color {
        match &self.0 {
            Shown::Ui(ui) => ui.base_color(),
            Shown::Failed(f) => f.look.bg,
        }
    }

    /// A `Waker` woke the UI thread.
    pub fn wake(&mut self, rr: &mut RenderRoot) {
        if let Shown::Ui(ui) = &mut self.0 {
            ui.wake(rr);
        }
    }

    /// A widget submitted an action.
    pub fn action(&mut self, rr: &mut RenderRoot, id: WidgetId, action: ErasedAction) {
        match &mut self.0 {
            Shown::Ui(ui) => ui.action(rr, id, action),
            Shown::Failed(f) => {
                if let Some(Frame(interval)) = action.downcast_ref::<Frame>().copied() {
                    f.host.frame(rr, interval);
                } else if f.fresh == Some(id) && action.downcast_ref::<ChipPress>().is_some() {
                    self.start_fresh(rr);
                }
            }
        }
    }
}
