//! kit's own widgets, drawn from a `Look` (notes/theming.md).

mod button;
mod chip;
mod grid;
mod limit;
mod panel;
mod root;
pub mod style;
mod tile;
mod wrap;

pub use button::IconButton;
pub use chip::{Chip, ChipMark, ChipPress};
pub use grid::{Reorder, TileGrid};
pub use limit::Limit;
pub use panel::{Panel, PanelKind};
pub use root::Root;
pub use tile::{Tile, TileIcon, TileStyle};
pub use wrap::Wrap;

/// What a pressed kit button or tile reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Press;

use crate::theme::Look;
use masonry::kurbo::{Affine, RoundedRect, Shape};
use masonry::peniko::{Color, Fill};
use masonry::vello::Scene;

/// Paints the theme's shadow under `shape` (`scale` of the theme's distance and softness).
pub(crate) fn shadow(scene: &mut Scene, look: &Look, rect: RoundedRect, scale: f64, xf: Affine) {
    if look.theme.shadow_opacity <= 0.0 || look.theme.shadow_distance <= 0.0 && look.theme.shadow_blur <= 0.0 {
        return;
    }
    let (dx, dy) = look.shadow_offset(scale);
    let blur = look.theme.shadow_blur * scale;
    let r = rect.rect();
    let radius = rect.radii().top_left;
    let at = xf * Affine::translate((dx, dy));
    if blur <= 0.5 {
        scene.fill(Fill::NonZero, at, look.shadow, None, &rect);
    } else {
        // a soft shadow pulled in by half its blur, as the CSS spread of -blur/2
        let inner = r.inset(-blur * 0.25);
        scene.draw_blurred_rounded_rect(at, inner, look.shadow, radius, blur * 0.5);
    }
}

/// Fills `shape` with `color` plus the theme's gloss.
pub(crate) fn fill_glossy(scene: &mut Scene, look: &Look, rect: RoundedRect, color: Color, xf: Affine) {
    scene.fill(Fill::NonZero, xf, color, None, &rect);
    let g = look.theme.gloss;
    if g > 0.0 {
        use masonry::peniko::Gradient;
        let r = rect.rect();
        let w = |a: f64| crate::theme::fade(Color::WHITE, a);
        let grad = Gradient::new_linear((r.x0, r.y0), (r.x0, r.y1)).with_stops([
            (0.0, w(g * 0.5)),
            (0.48, w(g * 0.16)),
            (0.5, w(0.0)),
            (1.0, w(g * 0.1)),
        ]);
        scene.fill(Fill::NonZero, xf, &grad, None, &rect.to_path(0.1));
    }
}
