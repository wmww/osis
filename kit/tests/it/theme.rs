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
