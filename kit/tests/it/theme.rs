//! Theme resolution: every default resolves in both modes to readable text on its background and
//! cards, and the background follows the main colour by bgTint.
use osis_kit::theme::{Look, Theme, lightness, mix, parse};

#[test]
fn defaults_resolve_readably() {
    let pink = parse("#ec4899");
    for t in Theme::defaults() {
        for dark in [false, true] {
            let l = Look::new(&t, dark, pink);
            let gap = (lightness(l.fg) - lightness(l.bg)).abs();
            assert!(gap > 0.5, "{} dark={dark}: text on background {gap}", t.id);
            let card = l.card(pink);
            assert!((lightness(l.card_fg()) - lightness(card)).abs() > 0.25, "{} dark={dark}: text on a card", t.id);
            assert_eq!(l.bg, mix(t.background.of(dark), pink.unwrap(), t.bg_tint));
        }
    }
    assert_eq!(Theme::named("nope").id, "frost");
    assert_eq!(Theme::named("cel").id, "cel");
}

/// Synced colour strings (a tag's colour can be any CSS colour another device wrote): every
/// resolved colour stays finite and in range, the background and accent opaque, and text on a
/// card of that colour readable.
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
                for (c, n) in [(l.bg, "bg"), (l.panel, "panel"), (l.accent, "accent"), (l.selection, "selection"), (l.main, "main"), (l.card(main), "card")] {
                    ok(c, &format!("{what} {n}"));
                }
                assert_eq!(l.bg.components[3], 1.0, "{what}: opaque background");
                assert_eq!(l.accent.components[3], 1.0, "{what}: opaque accent");
                let card = l.card(main);
                assert!((lightness(l.card_fg()) - lightness(card)).abs() > 0.25, "{what}: text on a card {} vs {}", lightness(l.card_fg()), lightness(card));
            }
        }
    }
}

/// Parameters at their extremes (notes/arbitrary-values.md: 0, huge, negative, NaN, for when
/// themes become data): resolved colours stay finite and in range, weights finite and within
/// their bounds.
#[test]
fn extreme_parameters_stay_finite() {
    let pink = parse("#ec4899");
    for v in [0.0, 1.0, -1e9, 1e9, f64::NAN, f64::INFINITY] {
        let mut t = Theme::named("glass");
        (t.bg_tint, t.panel_opacity, t.fill, t.shadow_opacity, t.gloss, t.weight) = (v, v, v, v, v, v);
        for dark in [false, true] {
            let l = Look::new(&t, dark, pink);
            for c in [l.bg, l.panel, l.accent, l.shadow, l.card(pink), l.card(None), l.icon_fill(pink)] {
                assert!(c.components.iter().all(|x| x.is_finite() && (0.0..=1.0).contains(x)), "{v}: {:?}", c.components);
            }
            let w = l.weight(400.0, 200.0, 100.0, 900.0);
            assert!(w.is_finite() && (100.0..=900.0).contains(&w), "{v}: weight {w}");
        }
    }
}
