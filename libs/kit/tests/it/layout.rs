//! The shell's layout follows the space it is given: the rail shows exactly when it and a page
//! fit side by side (a width from the look, not a constant), and Back on a page shows exactly when
//! the rail does not; the screen is rebuilt only when the rail comes or goes.
use crate::view_tree::data;
use osis_kit::masonry::app::{RenderRoot, RenderRootOptions, WindowSizePolicy};
use osis_kit::masonry::core::{WidgetId, WindowEvent};
use osis_kit::masonry::dpi::PhysicalSize;
use osis_kit::render::{ROOT, Ui, rail_needs, tree};
use osis_kit::store::Data;
use osis_kit::theme::{Look, Theme};
use osis_kit::window::Waker;
use std::sync::Arc;

struct Screen {
    ui: Ui,
    rr: RenderRoot,
    d: Data,
}

impl Screen {
    /// A note open in a window `width` wide, in `theme`.
    fn new(theme: &str, width: u32) -> Screen {
        let d = data();
        d.set_theme(theme).unwrap();
        let t = d.create_note().unwrap();
        d.set_open(Some(t)).unwrap();
        let ui = Ui::new(d.clone(), Waker::new(|| {})).unwrap();
        let opts = RenderRootOptions {
            default_properties: Arc::new(osis_kit::masonry::theme::default_property_set()),
            use_system_fonts: false,
            size_policy: WindowSizePolicy::User,
            size: PhysicalSize::new(width, 700),
            scale_factor: 1.0,
            test_font: None,
        };
        let rr = RenderRoot::new(tree(ui.look()), |_| {}, opts);
        let mut s = Screen { ui, rr, d };
        s.ui.start(&mut s.rr, Box::new(crate::input::Recorder::default()), 1.0, false);
        s.ui.wake(&mut s.rr);
        s
    }

    fn resize(&mut self, width: u32) {
        self.rr.handle_window_event(WindowEvent::Resize(PhysicalSize::new(width, 700)));
        self.ui.resized(&mut self.rr, 1.0);
    }

    /// What a screen reader is told is on screen.
    fn labels(&mut self) -> Vec<String> {
        self.rr.handle_window_event(WindowEvent::EnableAccessTree);
        let (_, update) = self.rr.redraw();
        update.unwrap().nodes.iter().filter_map(|(_, n)| n.label().map(str::to_string)).collect()
    }

    /// (the rail's Home row shows, the page's Back to home shows)
    fn rail_and_back(&mut self) -> (bool, bool) {
        let l = self.labels();
        (l.iter().any(|l| l == "osis: Home"), l.iter().any(|l| l == "Home"))
    }

    /// The screen under the root: a new one means everything on it was rebuilt.
    fn screen(&self) -> WidgetId {
        self.rr.get_widget_with_tag(ROOT).unwrap().children()[0].id()
    }
}

fn needs(theme: &str) -> f64 {
    rail_needs(&Look::new(&Theme::named(Some(theme)), false, None))
}

/// A window as wide as the rail and a page need shows the rail and no Back; a pixel less shows
/// Back and no rail. Within each, resizing rebuilds nothing.
#[test]
fn rail_shows_when_it_and_a_page_fit() {
    let at = needs("glass").ceil() as u32;
    let mut s = Screen::new("glass", at);
    assert_eq!(s.rail_and_back(), (true, false), "wide enough at {at}");
    let wide = s.screen();
    s.resize(at + 400);
    assert_eq!(s.screen(), wide, "wider still: nothing rebuilt");
    s.resize(at - 1);
    assert_eq!(s.rail_and_back(), (false, true), "too narrow at {}", at - 1);
    let narrow = s.screen();
    assert_ne!(narrow, wide);
    s.resize(200);
    assert_eq!(s.screen(), narrow, "narrower still: nothing rebuilt");
    assert_eq!(s.rail_and_back(), (false, true));
    s.resize(at);
    assert_eq!(s.rail_and_back(), (true, false));
}

/// The width the rail needs comes from the look: a theme with tighter spacing shows it in a
/// window where a roomier one does not.
#[test]
fn rail_needs_follow_the_look() {
    let (tight, roomy) = (needs("project"), needs("clarity"));
    assert!(tight < roomy, "project {tight}, clarity {roomy}");
    let between = ((tight + roomy) / 2.0) as u32;
    assert_eq!(Screen::new("project", between).rail_and_back(), (true, false));
    let mut s = Screen::new("clarity", between);
    assert_eq!(s.rail_and_back(), (false, true));
    // the theme changing under an open window moves the rail too
    s.d.set_theme("project").unwrap();
    s.ui.wake(&mut s.rr);
    assert_eq!(s.rail_and_back(), (true, false));
}

/// The rail needs its width clear of the window's insets: a side inset arriving after start can
/// take it away, and its going brings it back; top and bottom insets do not count. Insets are
/// physical pixels, so a new scale changes what they cover.
#[test]
fn insets_take_their_width() {
    let at = needs("glass").ceil() as u32;
    let mut s = Screen::new("glass", at + 10);
    assert_eq!(s.rail_and_back(), (true, false));
    s.ui.set_insets(&mut s.rr, [0.0, 300.0, 0.0, 300.0]);
    assert_eq!(s.rail_and_back(), (true, false), "top and bottom");
    s.ui.set_insets(&mut s.rr, [6.0, 0.0, 6.0, 0.0]);
    assert_eq!(s.rail_and_back(), (false, true), "left and right");
    // insets are physical: at twice the scale the same ones cover half as much
    s.rr.handle_window_event(WindowEvent::Rescale(2.0));
    s.rr.handle_window_event(WindowEvent::Resize(PhysicalSize::new(2 * (at + 10), 1400)));
    s.ui.resized(&mut s.rr, 2.0);
    assert_eq!(s.rail_and_back(), (true, false), "at scale 2");
    s.ui.set_insets(&mut s.rr, [12.0, 0.0, 12.0, 0.0]);
    assert_eq!(s.rail_and_back(), (false, true));
    s.ui.set_insets(&mut s.rr, [0.0; 4]);
    assert_eq!(s.rail_and_back(), (true, false));
}
