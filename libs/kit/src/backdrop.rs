//! Backgrounds (notes/theming.md `pattern`): background 1 with the theme's pattern drawn in
//! background 2 at varying opacity, no derived shades. Placement comes from seeds hashed from the
//! open thing (and its kind), so each thing keeps its own arrangement. Plain fills, gradients
//! and paths: no blur, no layers.

use crate::theme::{Look, Pattern, fade};
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

/// Paints the background of `size` with background colour `bg` (the look's, or a fade between
/// two).
pub fn paint(scene: &mut Scene, look: &Look, bg: Color, size: Size, seed: u64) {
    let (w, h) = (size.width, size.height);
    let r = Rect::from_origin_size((0.0, 0.0), size);
    let id = Affine::IDENTITY;
    scene.fill(Fill::NonZero, id, bg, None, &r);
    let s = seeds(seed);
    // the kind's small variation
    let k = seeds(seed ^ 0x5bd1_e995)[0];
    let deco = look.deco;
    let d = |a: f64| fade(deco, a);
    let big = w.max(h);
    match look.theme.pattern {
        Pattern::Flat => {}
        Pattern::Field => {
            for (i, (sx, sy, a)) in [(0.1 + s[0] * 0.45, s[1] * 0.35, 0.45), (0.45 + s[2] * 0.55, 0.55 + s[3] * 0.45, 0.4)].into_iter().enumerate() {
                let c = Point::new(w * sx, h * sy);
                let g = Gradient::new_radial(c, (big * (0.5 + 0.05 * i as f64) * 0.72) as f32).with_stops([(0.0, d(a)), (1.0, d(0.0))]);
                scene.fill(Fill::NonZero, id, &g, None, &r);
            }
        }
        Pattern::Curves => {
            // two large soft sheets curving across, one stronger
            for (top, rot, a) in [(h * (0.04 + 0.3 * s[1]), -22.0 + 18.0 * s[2], 0.4), (h * (0.48 + 0.26 * s[3]), -12.0 + 24.0 * k, 0.16)] {
                let (ew, eh) = (big * 1.1, big * 0.34);
                let c = Point::new(if a > 0.3 { -0.3 * big + ew / 2.0 } else { w + 0.4 * big - ew / 2.0 }, top + eh / 2.0);
                let xf = Affine::rotate_about(f64::to_radians(rot), c);
                let g = Gradient::new_linear((c.x, c.y - eh / 2.0), (c.x, c.y - eh / 2.0 + eh * 0.65)).with_stops([(0.0, d(a)), (1.0, d(0.0))]);
                scene.fill(Fill::NonZero, xf, &g, None, &masonry::kurbo::Ellipse::new(c, (ew / 2.0, eh / 2.0), 0.0));
            }
        }
        Pattern::Sky => {
            // background 2 at the top fading to background 1, a glow, and a swoosh
            let g = Gradient::new_linear((0.0, 0.0), (0.0, h * (0.55 + 0.15 * k))).with_stops([(0.0, deco), (1.0, d(0.0))]);
            scene.fill(Fill::NonZero, id, &g, None, &r);
            let gc = Point::new(w * (0.25 + 0.5 * s[0]), -0.06 * h);
            let g = Gradient::new_radial(gc, (w.max(h) * 0.45) as f32).with_stops([(0.0, d(0.7)), (1.0, d(0.0))]);
            scene.fill(Fill::NonZero, id, &g, None, &r);
            let top = h * (0.5 + 0.15 * s[2]);
            let c = Point::new(w / 2.0, top + h * 0.35);
            let xf = Affine::rotate_about(f64::to_radians(-7.0 + 8.0 * s[0]), c);
            let arc = masonry::kurbo::Ellipse::new(c, (w * 0.7, h * 0.35), 0.0);
            let g = Gradient::new_linear((0.0, top), (0.0, top + h * 0.7 * 0.25)).with_stops([(0.0, d(0.3)), (1.0, d(0.0))]);
            scene.fill(Fill::NonZero, xf, &g, None, &arc);
            scene.stroke(&Stroke::new(2.0), xf, d(0.8), None, &arc);
        }
        Pattern::Grid => {
            let step = 40.0;
            let st = Stroke::new(1.0);
            let mut x = 0.5;
            while x < w {
                scene.stroke(&st, id, d(0.45), None, &Line::new((x, 0.0), (x, h)));
                x += step;
            }
            let mut y = 0.5;
            while y < h {
                scene.stroke(&st, id, d(0.45), None, &Line::new((0.0, y), (w, y)));
                y += step;
            }
        }
        Pattern::Dots => {
            let step = 22.0;
            let mut y = step / 2.0;
            while y < h {
                let mut x = step / 2.0;
                while x < w {
                    scene.fill(Fill::NonZero, id, deco, None, &Circle::new((x, y), 1.5));
                    x += step;
                }
                y += step;
            }
        }
        Pattern::Shapes => {
            // a circle in background 2 ringed in the outline, a zigzag in the outline, a triangle in the panel colour
            let rr = big * 0.17;
            let c = Point::new(w + (0.14 - 0.1 * s[0]) * big - rr, (-0.16 + 0.12 * s[1]) * big + rr);
            scene.fill(Fill::NonZero, id, deco, None, &Circle::new(c, rr));
            scene.stroke(&Stroke::new(look.outline_width().max(1.0)), id, look.outline, None, &Circle::new(c, rr));
            let st = Stroke::new(7.0).with_caps(masonry::kurbo::Cap::Round).with_join(masonry::kurbo::Join::Round);
            let z = Point::new(w * (0.3 + 0.4 * s[2]), h * (1.0 - 0.03 - 0.08 * s[3]) - 25.0);
            let zr = Affine::rotate_about(f64::to_radians(-10.0 + 20.0 * s[0]), z);
            let mut zz = BezPath::new();
            for i in 0..11 {
                let p = (z.x - 125.0 + 25.0 * f64::from(i), z.y + if i % 2 == 0 { 15.0 } else { -15.0 });
                if i == 0 { zz.move_to(p) } else { zz.line_to(p) }
            }
            scene.stroke(&st, zr, look.outline, None, &zz);
            let t = Point::new(w * (0.02 + 0.08 * s[1]) + 75.0, h * (1.0 - 0.06 - 0.2 * s[2]) - 67.0);
            let rot = Affine::rotate_about(f64::to_radians(-30.0 + 60.0 * k), t);
            let mut tri = BezPath::new();
            tri.move_to((t.x, t.y - 67.0));
            tri.line_to((t.x + 75.0, t.y + 67.0));
            tri.line_to((t.x - 75.0, t.y + 67.0));
            tri.close_path();
            scene.fill(Fill::NonZero, rot, look.surface, None, &tri);
        }
        Pattern::Lines => {
            // two or three parallel lines: widths, spacing, angle and offset from the seeds
            let widths = [3.0 + s[0] * 14.0, 1.0 + s[1] * 6.0, (s[3] - 0.5).max(0.0) * 30.0];
            let gaps = [14.0 + s[2] * 40.0, 8.0 + s[0] * 26.0];
            let c = Point::new(w / 2.0, h / 2.0);
            let xf = Affine::translate(((s[2] * 0.6 - 0.3) * w, 0.0)) * Affine::rotate_about(f64::to_radians(8.0 + 55.0 * s[1] + 20.0 * k), c);
            let mut x = c.x;
            for (i, lw) in widths.into_iter().enumerate() {
                if lw > 0.0 {
                    scene.fill(Fill::NonZero, xf, deco, None, &Rect::new(x, c.y - big * 2.0, x + lw, c.y + big * 2.0));
                }
                x += lw + gaps.get(i).copied().unwrap_or(0.0);
            }
        }
        Pattern::Beams => {
            // light through water: bands fanning from a seeded point above the top, fading downwards
            let o = Point::new(w * (0.15 + 0.7 * s[1]), -0.25 * h);
            for i in 0..9u64 {
                let ss = seeds(seed.wrapping_add(i * 7 + 3));
                let ang = f64::to_radians(-35.0 + 70.0 * ss[0] + 10.0 * s[3]);
                let spread = f64::to_radians(1.0 + 2.5 * ss[1]);
                let len = h * 1.6;
                let mut p = BezPath::new();
                p.move_to(o);
                p.line_to((o.x + len * (ang - spread).sin(), o.y + len * (ang - spread).cos()));
                p.line_to((o.x + len * (ang + spread).sin(), o.y + len * (ang + spread).cos()));
                p.close_path();
                let a = (0.45 + 0.3 * ss[2]) * 0.6;
                let g = Gradient::new_linear((0.0, 0.0), (0.0, h * (0.6 + 0.25 * s[3]))).with_stops([(0.0, d(a)), (1.0, d(0.0))]);
                scene.fill(Fill::NonZero, id, &g, None, &p);
            }
        }
        Pattern::Grass => {
            // two layers of blades rising from the bottom, the back one taller and fainter
            for (layer, (tall, a, step)) in [(0.26 + 0.16 * s[1], 0.45, 13.0), (0.14 + 0.1 * s[3], 0.8, 9.0)].into_iter().enumerate() {
                let n = (w / step) as usize + 2;
                for i in 0..n {
                    let ss = seeds(seed.wrapping_add(i as u64 * 13 + 5 + layer as u64 * 1000));
                    let x = i as f64 * step + ss[0] * step * 0.7 - step * (s[0] + s[2]);
                    let len = h * tall * (0.3 + 0.7 * ss[1]);
                    let lean = (ss[2] - 0.5) * len * 0.5;
                    let mut blade = BezPath::new();
                    blade.move_to((x - 4.0, h));
                    blade.quad_to((x, h - len * 0.6), (x + lean, h - len));
                    blade.quad_to((x + 2.0, h - len * 0.5), (x + 4.0, h));
                    blade.close_path();
                    scene.fill(Fill::NonZero, id, d(a), None, &blade);
                }
            }
        }
    }
}
