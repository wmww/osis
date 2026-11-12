//! Theme resolution: every default resolves in both modes to readable text on its background and
//! cards, and each colour takes the contextual colour by its dynamic.
use osis_kit::theme::{Look, Theme, lightness, mix, over, parse};

/// Text on a card: its bottom (where the name sits), on what is under it.
fn card_gap(l: &Look, tint: Option<osis_kit::masonry::peniko::Color>) -> f64 {
    let c = l.card(tint);
    let under = if l.panel_opacity() > 0.0 { over(l.bg, l.panel) } else { l.bg };
    (lightness(c.fg) - lightness(over(under, c.bottom))).abs()
}

#[test]
fn defaults_resolve_readably() {
    let pink = parse("#ec4899");
    for t in Theme::defaults() {
        for dark in [false, true] {
            let l = Look::new(&t, dark, pink);
            let gap = (lightness(l.fg) - lightness(l.bg)).abs();
            assert!(gap > 0.5, "{} dark={dark}: text on background {gap}", t.id);
            assert!(card_gap(&l, pink) > 0.25, "{} dark={dark}: text on a card", t.id);
            let base = if dark { t.bg1.dark } else { t.bg1.light };
            assert_eq!(l.bg, mix(base.with_alpha(1.0), pink.unwrap(), t.bg1.dynamic));
        }
    }
    assert_eq!(Theme::named(Some("nope")).id, "clarity");
    assert_eq!(Theme::named(None).id, "clarity");
    assert_eq!(Theme::named(Some("velocity")).id, "velocity");
}

/// Synced colour strings (a tag's colour can be any CSS colour another node wrote): every
/// resolved colour stays finite and in range, the background opaque, and text on a card of that
/// colour readable.
#[test]
fn odd_main_colours_resolve_sanely() {
    use osis_kit::masonry::peniko::Color;
    let odd = ["transparent", "#0000", "rgba(255, 0, 0, 0.05)", "color(srgb 1e30 -1e30 0)", "oklch(5 900 0)", "lab(1000 1000 1000)", "#ffffff", "#ffff00", "#000000", "hsl(60 100% 95%)"];
    let ok = |c: Color, what: &str| {
        assert!(c.components.iter().all(|x| x.is_finite() && (0.0..=1.0).contains(x)), "{what}: {:?}", c.components);
    };
    for s in odd {
        let main = parse(s);
        for t in Theme::defaults() {
            for dark in [false, true] {
                let l = Look::new(&t, dark, main);
                let what = format!("{s} {} dark={dark}", t.id);
                let c = l.card(main);
                for (c, n) in [(l.bg, "bg"), (l.deco, "deco"), (l.panel, "panel"), (l.accent, "accent"), (l.selection, "selection"), (l.main, "main"), (c.top, "card top"), (c.bottom, "card bottom")] {
                    ok(c, &format!("{what} {n}"));
                }
                assert_eq!(l.bg.components[3], 1.0, "{what}: opaque background");
                let gap = card_gap(&l, main);
                assert!(gap > 0.25, "{what}: text on a card {gap}");
            }
        }
    }
}

/// Parameters at their extremes (notes/arbitrary-values.md: 0, huge, negative, NaN, for when
/// themes become data): resolved colours and sizes stay finite and in range.
#[test]
fn extreme_parameters_stay_finite() {
    let pink = parse("#ec4899");
    for v in [0.0, 1.0, -1e9, 1e9, f64::NAN, f64::INFINITY] {
        let mut t = Theme::named(Some("glass"));
        for c in [&mut t.bg1, &mut t.bg2, &mut t.panel, &mut t.card_top, &mut t.card_bottom, &mut t.text, &mut t.shadow] {
            c.dynamic = v;
        }
        (t.text_size, t.text_weight, t.heading_size, t.heading_weight, t.grad_pos, t.grad_spread) = (v, v, v, v, v, v);
        (t.spacing, t.radius, t.slant, t.icon_round, t.shadow_blur, t.shadow_distance, t.shadow_angle, t.outline_width) = (v, v, v, v, v, v, v, v);
        for dark in [false, true] {
            let l = Look::new(&t, dark, pink);
            let c = l.card(pink);
            for c in [l.bg, l.panel, l.accent, l.shadow, c.top, c.bottom, c.icon_bg, l.card(None).bottom] {
                assert!(c.components.iter().all(|x| x.is_finite() && (0.0..=1.0).contains(x)), "{v}: {:?}", c.components);
            }
            for w in [l.text_weight(), l.name_weight(), l.heading_weight()] {
                assert!(w.is_finite() && (100.0..=900.0).contains(&w), "{v}: weight {w}");
            }
            let (a, b) = l.card_stops();
            let (dx, dy) = l.shadow_offset(1.5);
            for x in [l.sp(10.0), f64::from(l.text_px(10.0)), f64::from(l.heading_px(10.0)), a, b, dx, dy, l.shadow_blur(2.5), l.radius(), l.shear(), l.icon_shear(), l.outline_width()] {
                assert!(x.is_finite(), "{v}: {x}");
            }
        }
    }
}
