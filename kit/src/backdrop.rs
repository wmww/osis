//! Backgrounds (notes/theming.md `background`): the window colour plus the theme's decoration,
//! every decoration a lighter or darker shade of the background colour. Placement comes from a
//! seed hashed from the open thing.

use crate::theme::{Backdrop, Look, lightness, mix};
use masonry::kurbo::{Affine, Rect, Size};
use masonry::peniko::{Color, Fill, Gradient};
use masonry::vello::Scene;

/// Four numbers in [0, 1) from `seed`.
pub fn seeds(seed: u64) -> [f64; 4] {
    let mut h = seed ^ 0x9e37_79b9_7f4a_7c15;
    let mut out = [0.0; 4];
    for s in &mut out {
        h = h.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
        *s = ((h >> 33) % 1000) as f64 / 1000.0;
    }
    out
}

/// A shade of the background: `d` > 0 lighter, < 0 darker.
pub fn shade(bg: Color, d: f64) -> Color {
    if d >= 0.0 { mix(bg, Color::WHITE, d) } else { mix(bg, Color::BLACK, -d) }
}

pub fn paint(scene: &mut Scene, look: &Look, size: Size, seed: u64) {
    let r = Rect::from_origin_size((0.0, 0.0), size);
    let bg = look.bg;
    scene.fill(Fill::NonZero, Affine::IDENTITY, bg, None, &r);
    let s = seeds(seed);
    // decorations step toward the far end: lighter on dark backgrounds, darker on light ones
    let dir = if lightness(bg) > 0.5 { -1.0 } else { 1.0 };
    match look.theme.backdrop {
        Backdrop::Flat => {}
        _ => {
            // a soft glow of a lighter shade, placed by the seed
            let c = (size.width * (0.2 + 0.6 * s[0]), size.height * (0.1 + 0.4 * s[1]));
            let rad = size.width.max(size.height) * (0.5 + 0.3 * s[2]);
            let hi = shade(bg, -dir * 0.12);
            let g = Gradient::new_radial(c, rad as f32).with_stops([(0.0, hi), (1.0, hi.with_alpha(0.0))]);
            scene.fill(Fill::NonZero, Affine::IDENTITY, &g, None, &r);
        }
    }
}
