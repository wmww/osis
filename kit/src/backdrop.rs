//! Backgrounds (notes/theming.md `background`): the window colour plus the theme's decoration,
//! every decoration a lighter or darker shade of the background colour, never tinted on its own.
//! Placement comes from four seeds hashed from the open thing (and its kind), so each thing keeps
//! its own arrangement. Plain fills, gradients and paths: no blur, no layers.

use crate::theme::{Backdrop, Look, fade, lightness, mix};
use masonry::kurbo::{Affine, BezPath, Circle, Line, Point, Rect, Size, Stroke};
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

/// Paints the background of `size` with background colour `bg` (the look's, or a fade between
/// two).
pub fn paint(scene: &mut Scene, look: &Look, bg: Color, size: Size, seed: u64) {
    let (w, h) = (size.width, size.height);
    let r = Rect::from_origin_size((0.0, 0.0), size);
    let id = Affine::IDENTITY;
    scene.fill(Fill::NonZero, id, bg, None, &r);
    let s = seeds(seed);
    let light = lightness(bg) > 0.5;
    // `deco`: a shade that reads against the background; `hi`: the other way, softer
    let deco = shade(bg, if light { -0.07 } else { 0.07 });
    let hi = shade(bg, if light { 0.35 } else { -0.25 });
    let big = w.max(h);
    match look.theme.backdrop {
        Backdrop::Flat => {}
        Backdrop::Field => {
            for (i, (sx, sy)) in [(s[0], s[1]), (s[2], s[3])].into_iter().enumerate() {
                let c = Point::new(w * sx, h * sy);
                let col = if i == 0 { deco } else { hi };
                let g = Gradient::new_radial(c, (big * (0.45 + 0.2 * sx)) as f32).with_stops([(0.0, col), (1.0, col.with_alpha(0.0))]);
                scene.fill(Fill::NonZero, id, &g, None, &r);
            }
        }
        Backdrop::Curves => {
            // two soft bands sweeping across, darker below a seeded curve
            for (i, (col, sa, sb)) in [(deco, s[0], s[1]), (shade(bg, if light { -0.04 } else { 0.04 }), s[1], s[2])].into_iter().enumerate() {
                let y0 = h * (0.45 + 0.3 * sa + 0.1 * i as f64);
                let mut p = BezPath::new();
                p.move_to((0.0, y0));
                p.curve_to((w * 0.3, y0 - h * (0.25 + 0.2 * s[2])), (w * 0.65, y0 + h * (0.2 * s[3] - 0.05)), (w, y0 - h * 0.2 * sb));
                p.line_to((w, h));
                p.line_to((0.0, h));
                p.close_path();
                let g = Gradient::new_linear((0.0, y0 - h * 0.3), (0.0, h)).with_stops([(0.0, col), (1.0, fade(col, 0.4))]);
                scene.fill(Fill::NonZero, id, &g, None, &p);
            }
        }
        Backdrop::Sky => {
            let top = shade(bg, if light { -0.12 } else { 0.1 });
            let g = Gradient::new_linear((0.0, 0.0), (0.0, h)).with_stops([(0.0, top), (0.7, bg), (1.0, shade(bg, if light { 0.2 } else { -0.15 }))]);
            scene.fill(Fill::NonZero, id, &g, None, &r);
            // a light swoosh
            let y = h * (0.55 + 0.25 * s[0]);
            let mut p = BezPath::new();
            p.move_to((-w * 0.1, y));
            p.curve_to((w * 0.3, y - h * 0.35 * (0.5 + s[1])), (w * 0.7, y + h * 0.1), (w * 1.1, y - h * 0.3 * s[2]));
            let sw = Stroke::new(h * (0.08 + 0.06 * s[3]));
            scene.stroke(&sw, id, fade(shade(bg, if light { 0.5 } else { 0.12 }), 0.35), None, &p);
        }
        Backdrop::Grid => {
            let step = 32.0;
            let off = (s[0] * step, s[1] * step);
            let st = Stroke::new(1.0);
            let mut x = off.0;
            while x < w {
                scene.stroke(&st, id, deco, None, &Line::new((x, 0.0), (x, h)));
                x += step;
            }
            let mut y = off.1;
            while y < h {
                scene.stroke(&st, id, deco, None, &Line::new((0.0, y), (w, y)));
                y += step;
            }
        }
        Backdrop::Dots => {
            let step = 22.0;
            let dot = shade(bg, if light { -0.12 } else { 0.12 });
            let mut y = s[1] * step;
            while y < h {
                let mut x = s[0] * step;
                while x < w {
                    scene.fill(Fill::NonZero, id, dot, None, &Circle::new((x, y), 1.4));
                    x += step;
                }
                y += step;
            }
        }
        Backdrop::Shapes => {
            // three shapes: a ring, a triangle, a zigzag
            let col = shade(bg, if light { -0.1 } else { 0.1 });
            let st = Stroke::new(10.0).with_caps(masonry::kurbo::Cap::Round).with_join(masonry::kurbo::Join::Round);
            let c = Point::new(w * (0.75 + 0.2 * s[0]), h * (0.15 + 0.25 * s[1]));
            scene.stroke(&st, id, col, None, &Circle::new(c, 60.0 + 40.0 * s[2]));
            let t = Point::new(w * (0.05 + 0.2 * s[1]), h * (0.6 + 0.3 * s[2]));
            let rot = Affine::rotate_about(s[3] * std::f64::consts::TAU, t);
            let mut tri = BezPath::new();
            tri.move_to((t.x, t.y - 60.0));
            tri.line_to((t.x + 55.0, t.y + 40.0));
            tri.line_to((t.x - 55.0, t.y + 40.0));
            tri.close_path();
            scene.fill(Fill::NonZero, rot, shade(bg, if light { -0.06 } else { 0.06 }), None, &tri);
            let z = Point::new(w * (0.45 + 0.3 * s[3]), h * (0.8 + 0.1 * s[0]));
            let mut zz = BezPath::new();
            zz.move_to(z);
            for i in 1..7 {
                zz.line_to((z.x + 30.0 * f64::from(i), z.y + if i % 2 == 0 { 0.0 } else { -28.0 }));
            }
            scene.stroke(&st, id, col, None, &zz);
        }
        Backdrop::Lines => {
            // two or three bold parallel lines at a seeded angle
            let n = 2 + (s[3] * 2.0) as usize;
            let angle = (-0.35 + 0.7 * s[0]) + std::f64::consts::FRAC_PI_4;
            let rot = Affine::rotate_about(angle, Point::new(w / 2.0, h / 2.0));
            let col = shade(bg, if light { -0.08 } else { 0.08 });
            let base = h * (0.2 + 0.5 * s[1]);
            let gap = 30.0 + 50.0 * s[2];
            for i in 0..n {
                let width = 8.0 + 22.0 * seeds(seed.wrapping_add(i as u64 + 1))[0];
                let y = base + i as f64 * gap;
                scene.stroke(&Stroke::new(width), rot, col, None, &Line::new((-big, y), (w + big, y)));
            }
        }
        Backdrop::Beams => {
            // light through water from above: slanted bands, clear-light-clear sideways
            let light_col = shade(bg, if light { 0.45 } else { 0.1 });
            for i in 0..5 {
                let ss = seeds(seed.wrapping_add(i * 7 + 3));
                let x = w * ss[0];
                let bw = 40.0 + 120.0 * ss[1];
                let tilt = Affine::skew(-0.25 - 0.2 * s[0], 0.0);
                let g = Gradient::new_linear((x, 0.0), (x + bw, 0.0)).with_stops([(0.0, fade(light_col, 0.0)), (0.5, fade(light_col, 0.25 + 0.3 * ss[2])), (1.0, fade(light_col, 0.0))]);
                let band = Rect::new(x, 0.0, x + bw, h * (0.6 + 0.4 * ss[3]));
                scene.fill(Fill::NonZero, tilt, &g, None, &band);
            }
            // fade the beams out downwards
            let g = Gradient::new_linear((0.0, h * 0.3), (0.0, h)).with_stops([(0.0, bg.with_alpha(0.0)), (1.0, bg)]);
            scene.fill(Fill::NonZero, id, &g, None, &r);
        }
        Backdrop::Grass => {
            let n = (w / 9.0) as usize;
            for i in 0..n {
                let ss = seeds(seed.wrapping_add(i as u64 * 13 + 5));
                let x = i as f64 * 9.0 + ss[0] * 6.0;
                let len = h * (0.06 + 0.14 * ss[1] * (0.6 + 0.4 * (x / w * 3.0 + s[0] * 6.0).sin().abs()));
                let lean = (ss[2] - 0.5) * len * 0.6;
                let mut blade = BezPath::new();
                blade.move_to((x - 3.0, h));
                blade.quad_to((x, h - len * 0.6), (x + lean, h - len));
                blade.quad_to((x + 1.0, h - len * 0.5), (x + 3.0, h));
                blade.close_path();
                let col = shade(bg, (if light { -0.08 } else { 0.08 }) * (0.6 + 0.6 * ss[3]));
                scene.fill(Fill::NonZero, id, col, None, &blade);
            }
        }
    }
}
