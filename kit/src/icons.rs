//! Line icons on a 24-unit grid, as SVG path data (stroked, round caps), drawn by `paint`.

use masonry::kurbo::{Affine, BezPath, Cap, Join, Stroke};
use masonry::peniko::Color;
use masonry::vello::Scene;

/// A named icon.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Icon {
    Note,
    Event,
    Calendar,
    Contact,
    People,
    Tag,
    Tags,
    Recent,
    Search,
    Star,
    Back,
    Plus,
    Eye,
    Clock,
    Trash,
    Home,
    List,
}

/// A circle as path data.
macro_rules! circle {
    ($cx:literal, $cy:literal, $r:literal, $d:literal) => {
        concat!("M", $cx, " ", $cy, "m-", $r, " 0a", $r, " ", $r, " 0 1 0 ", $d, " 0a", $r, " ", $r, " 0 1 0 -", $d, " 0")
    };
}

impl Icon {
    fn data(self) -> &'static str {
        match self {
            Icon::Note => "M6 3h8l4 4v14H6z M14 3v4h4M9 12h6M9 16h4",
            Icon::Event => "M6.5 5h11a2.5 2.5 0 0 1 2.5 2.5v10a2.5 2.5 0 0 1-2.5 2.5h-11a2.5 2.5 0 0 1-2.5-2.5v-10a2.5 2.5 0 0 1 2.5-2.5z M4 10h16M9 3v4M15 3v4",
            Icon::Calendar => "M6.5 5h11a2.5 2.5 0 0 1 2.5 2.5v10a2.5 2.5 0 0 1-2.5 2.5h-11a2.5 2.5 0 0 1-2.5-2.5v-10a2.5 2.5 0 0 1 2.5-2.5z M4 10h16M9 3v4M15 3v4 M8 14h.01M12 14h.01M16 14h.01M8 17h.01M12 17h.01",
            Icon::Contact => concat!(circle!(12, 9, 3.6, 7.2), " M5 20c.9-3.6 3.6-5.4 7-5.4s6.1 1.8 7 5.4"),
            Icon::People => concat!(circle!(9, 9, 3.2, 6.4), " ", circle!(17, 10, 2.4, 4.8), " M3 20c.7-3.3 3-5 6-5s5.3 1.7 6 5M15.5 15.2c2.6-.2 4.6 1.2 5.5 4.3"),
            Icon::Tag => concat!("M3.5 12.5V4.5h8l9 9-8 8z ", circle!(8, 9, 1.4, 2.8)),
            Icon::Tags => concat!("M2.5 13V6h7l8 8-6.5 6.5z M12 6h1.5l8 8L15 20.5 ", circle!(6.5, 10, 1.2, 2.4)),
            Icon::Recent | Icon::Clock => concat!(circle!(12, 12, 8.5, 17), " M12 7.5V12l3 2"),
            Icon::Search => concat!(circle!(11, 11, 6.5, 13), " M20 20l-4.2-4.2"),
            Icon::Star => "M12 3.5l2.6 5.3 5.9.9-4.3 4.1 1 5.8L12 16.8l-5.2 2.8 1-5.8-4.3-4.1 5.9-.9z",
            Icon::Back => "M15 5l-7 7 7 7",
            Icon::Plus => "M12 5v14M5 12h14",
            Icon::Eye => concat!("M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z ", circle!(12, 12, 2.8, 5.6)),
            Icon::Trash => "M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3",
            Icon::Home => "M4 11l8-7 8 7v9h-5v-6h-6v6H4z",
            Icon::List => "M9 6h11M9 12h11M9 18h11M4.5 6h.01M4.5 12h.01M4.5 18h.01",
        }
    }

    pub fn path(self) -> BezPath {
        BezPath::from_svg(self.data()).unwrap_or_default()
    }

    /// Strokes the icon into a `size` square at `at` (top left); `filled` also fills it.
    pub fn paint(self, scene: &mut Scene, at: (f64, f64), size: f64, color: Color, filled: bool) {
        let k = size / 24.0;
        let xf = Affine::translate(at) * Affine::scale(k);
        let path = self.path();
        if filled {
            scene.fill(masonry::peniko::Fill::NonZero, xf, color, None, &path);
        }
        let stroke = Stroke::new(1.8).with_caps(Cap::Round).with_join(Join::Round);
        scene.stroke(&stroke, xf, color, None, &path);
    }
}
