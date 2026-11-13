//! kit's own widgets, drawn from a `Look` (notes/theming.md).

mod button;
mod chip;
mod grid;
mod mark;
mod menu;
mod page;
mod panel;
mod root;
pub mod style;
mod tile;
mod vlist;
pub(crate) use vlist::LAID_OUT;
mod wrap;

pub use button::IconButton;
pub use chip::{Chip, ChipMark, ChipPress};
pub use grid::TileGrid;
pub use mark::Mark;
pub use menu::{Menu, MenuItem, MenuPick};
pub use page::Page;
pub use panel::{Blur, Panel, PanelKind};
pub use root::{Frame, Root};
pub use tile::{ROW_MIN, Tile, TileIcon, TileStyle};
pub use vlist::{GUTTER, ListAction, VirtualList};
pub use wrap::Wrap;

/// What a pressed kit button or tile reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Press;

use crate::theme::{Card, Look};
use masonry::kurbo::{Affine, Rect, RoundedRect, Shape, Size};
use masonry::peniko::{Color, Fill, Gradient};
use masonry::vello::Scene;

/// The theme's slant as a transform for a box of `size`, leaning about its centre.
pub(crate) fn lean(shear: f64, size: Size) -> Affine {
    Affine::translate((size.height * 0.5 * shear, 0.0)) * Affine::skew(-shear, 0.0)
}

/// Paints the theme's shadow (`color`, usually `look.shadow`) under `rect` at `(distance,
/// softness)` scales of the theme's. As in CSS, none of it shows through the box itself, so a
/// see-through fill never shows its own shadow.
pub(crate) fn shadow(scene: &mut Scene, look: &Look, rect: RoundedRect, (off, soft): (f64, f64), color: Color, xf: Affine) {
    let (dx, dy) = look.shadow_offset(off);
    let blur = look.shadow_blur(soft);
    if color.components[3] <= 0.0 || dx.hypot(dy) <= 0.0 && blur <= 0.0 {
        return;
    }
    let r = rect.rect();
    let radius = rect.radii().top_left;
    let at = xf * Affine::translate((dx, dy));
    // everything but the box: a big rect with the box cut out (opposite winding)
    let reach = blur * 2.0 + dx.abs() + dy.abs() + 4.0;
    let mut hole = Rect::from_points((r.x0 - reach, r.y0 - reach), (r.x1 + reach, r.y1 + reach)).to_path(0.1);
    hole.extend(rect.to_path(0.1).reverse_subpaths());
    scene.push_clip_layer(xf, &hole);
    if blur <= 0.5 {
        scene.fill(Fill::NonZero, at, color, None, &rect);
    } else {
        // a soft shadow pulled in by half its blur, as the CSS spread of -blur/2
        let inner = r.inset(-blur * 0.25);
        scene.draw_blurred_rounded_rect(at, inner, color, radius, blur * 0.5);
    }
    scene.pop_layer();
}

/// Fills `rect` with a card's gradient: card top to card bottom, the change centred at the
/// theme's gradient position over its spread (0: a hard line).
pub(crate) fn fill_card(scene: &mut Scene, look: &Look, rect: RoundedRect, card: &Card, xf: Affine) {
    if card.top == card.bottom {
        scene.fill(Fill::NonZero, xf, card.bottom, None, &rect);
        return;
    }
    let r = rect.rect();
    let (a, b) = look.card_stops();
    let y = |f: f64| r.y0 + r.height() * f;
    // a zero spread is a hard line: two stops a hair apart
    let (ya, yb) = (y(a), y(b).max(y(a) + 0.01));
    let g = Gradient::new_linear((r.x0, ya), (r.x0, yb)).with_stops([(0.0, card.top), (1.0, card.bottom)]);
    scene.fill(Fill::NonZero, xf, &g, None, &rect);
}

/// `c` a little brighter (a hovered card).
pub(crate) fn brighten(c: Color) -> Color {
    let [r, g, b, a] = c.components;
    Color::new([(r * 1.04).min(1.0), (g * 1.04).min(1.0), (b * 1.04).min(1.0), a])
}

