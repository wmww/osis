//! Themes (notes/theming.md): a theme is a fixed set of parameters, never code. `Theme` holds
//! them, `Theme::defaults` the six built-ins, and `Look::new` resolves a theme, a mode and the
//! screen's main colour into the concrete colours and sizes the kit widgets draw with. Every
//! widget takes its look from a `Look`; changing theme, mode or main colour means a new `Look`.
//! A sub-view standing for a thing of its own (a tile, chip, avatar) resolves its colours in that
//! thing's colour (`Look::card`).

use masonry::peniko::Color;
use masonry::peniko::color::{AlphaColor, Oklab, Srgb, parse_color};

/// Light or dark (a user setting outside the theme); `Auto` follows the system.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Mode {
    #[default]
    Auto,
    Light,
    Dark,
}

/// A theme colour: one per mode, plus how much of the contextual colour mixes in (0..1, in
/// Oklab, the mode's alpha kept).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Colour {
    pub light: Color,
    pub dark: Color,
    pub dynamic: f64,
}

impl Colour {
    /// The colour in mode `dark` with `ctx` (the contextual colour) mixed in by `dynamic`.
    pub fn of(&self, dark: bool, ctx: Color) -> Color {
        let base = if dark { self.dark } else { self.light };
        let a = base.components[3];
        let a = if a.is_finite() { a.clamp(0.0, 1.0) } else { 1.0 };
        mix(base.with_alpha(1.0), ctx, self.dynamic).with_alpha(a)
    }
}

/// What a theme draws behind everything (one per theme), in background 1 and 2 only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pattern {
    Flat,
    Field,
    Curves,
    Sky,
    Grid,
    Dots,
    Shapes,
    Lines,
    Beams,
    Grass,
}

/// A mark in the main colour on headings: an underline under titles; a slash (leaning with
/// slant) or a dot before section labels and before titles with nothing else there (the dot
/// also after the brand).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeadingMark {
    None,
    Underline,
    Slash,
    Dot,
}

/// The case of section labels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LabelCase {
    None,
    Upper,
    Lower,
}

/// The theme fonts (all OFL except the platform's own).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Font {
    System,
    Inter,
    DmSans,
    Figtree,
    Lexend,
    Atkinson,
    Nunito,
    Literata,
    JetBrainsMono,
}

/// A theme's parameters (notes/theming.md Parameters).
#[derive(Clone, Debug, PartialEq)]
pub struct Theme {
    pub id: &'static str,
    pub name: &'static str,
    pub pattern: Pattern,
    /// The page (drawn opaque).
    pub bg1: Colour,
    /// The pattern's decorations.
    pub bg2: Colour,
    pub text_font: Font,
    /// Running text; muted text is a fade of it.
    pub text: Colour,
    /// A factor on every text size.
    pub text_size: f64,
    /// 100..900; names are a step bolder.
    pub text_weight: f64,
    /// Links, the caret.
    pub accent: Colour,
    /// Titles, the brand, section labels.
    pub heading_font: Font,
    pub heading: Colour,
    pub heading_size: f64,
    pub heading_weight: f64,
    pub mark: HeadingMark,
    pub label_case: LabelCase,
    /// Panels are flat; its alpha is panel opacity, which the panel outline and shadow follow.
    pub panel: Colour,
    /// Cards (tiles, the selected row, chips) run from top to bottom.
    pub card_top: Colour,
    pub card_bottom: Colour,
    /// 0 top .. 1 bottom: where the change from card top to bottom is centred.
    pub grad_pos: f64,
    /// 0..1 of the height; 0 is a hard line.
    pub grad_spread: f64,
    /// px; unused (no backdrop blur in Vello) but for a faint lit top edge on panels.
    pub panel_blur: f64,
    /// px.
    pub radius: f64,
    /// A factor on every padding, gap and margin.
    pub spacing: f64,
    /// deg; cards, fields, icon backgrounds and the slash mark lean, text stays upright.
    pub slant: f64,
    /// 0 square .. 1 circle.
    pub icon_round: f64,
    /// Its alpha is shadow opacity.
    pub shadow: Colour,
    pub shadow_blur: f64,
    pub shadow_distance: f64,
    /// deg, 90 = straight down.
    pub shadow_angle: f64,
    pub outline: Colour,
    /// px; panels and fields only.
    pub outline_width: f64,
}

fn hex(s: &str) -> Color {
    parse_color(s).map(|c| c.to_alpha_color::<Srgb>()).unwrap_or(Color::from_rgb8(128, 128, 128))
}

fn c(l: &str, d: &str, dynamic: f64) -> Colour {
    Colour { light: hex(l), dark: hex(d), dynamic }
}

/// The theme a store that chose none uses.
pub const DEFAULT: &str = "clarity";

impl Theme {
    /// The six built-in themes (the mockup's themes.js values).
    pub fn defaults() -> Vec<Theme> {
        vec![
            Theme {
                id: "clarity",
                name: "Clarity",
                pattern: Pattern::Curves,
                bg1: c("#f2f3f7", "#0f1117", 0.1),
                bg2: c("#d6d8e0", "#252833", 0.15),
                text_font: Font::System,
                text: c("#16151c", "#f1f1f6", 0.0),
                text_size: 1.0,
                text_weight: 400.0,
                accent: c("#000000", "#ffffff", 0.65),
                heading_font: Font::System,
                heading: c("#16151c", "#f1f1f6", 0.0),
                heading_size: 1.0,
                heading_weight: 700.0,
                mark: HeadingMark::None,
                label_case: LabelCase::None,
                panel: c("#ffffff00", "#1f212900", 0.0),
                card_top: c("#ffffff9e", "#1f21299e", 0.1),
                card_bottom: c("#ffffff9e", "#1f21299e", 0.18),
                grad_pos: 0.5,
                grad_spread: 1.0,
                panel_blur: 0.0,
                radius: 18.0,
                spacing: 1.1,
                slant: 0.0,
                icon_round: 1.0,
                shadow: c("#14203c4d", "#0000008a", 0.0),
                shadow_blur: 18.0,
                shadow_distance: 6.0,
                shadow_angle: 90.0,
                outline: c("#16151c", "#f1f1f6", 0.0),
                outline_width: 0.0,
            },
            Theme {
                id: "glass",
                name: "Glass",
                pattern: Pattern::Sky,
                bg1: c("#e6eef8", "#07101e", 0.4),
                bg2: c("#8193b0", "#22345a", 0.6),
                text_font: Font::Figtree,
                text: c("#16151c", "#f1f1f6", 0.0),
                text_size: 1.0,
                text_weight: 400.0,
                accent: c("#000000", "#ffffff", 0.65),
                heading_font: Font::Figtree,
                heading: c("#16151c", "#f1f1f6", 0.0),
                heading_size: 1.0,
                heading_weight: 600.0,
                mark: HeadingMark::None,
                label_case: LabelCase::None,
                panel: c("#ffffff8c", "#18223a8c", 0.0),
                card_top: c("#ffffff", "#ffffff", 0.72),
                card_bottom: c("#ffffff", "#000000", 0.94),
                grad_pos: 0.5,
                grad_spread: 0.4,
                panel_blur: 24.0,
                radius: 14.0,
                spacing: 1.0,
                slant: 0.0,
                icon_round: 1.0,
                shadow: c("#00205059", "#000000a1", 0.0),
                shadow_blur: 16.0,
                shadow_distance: 7.0,
                shadow_angle: 90.0,
                outline: c("#16151c", "#f1f1f6", 0.0),
                outline_width: 0.0,
            },
            Theme {
                id: "project",
                name: "Project",
                pattern: Pattern::Grid,
                bg1: c("#d4d4e2", "#0d0e18", 0.12),
                bg2: c("#b6b6c8", "#24263a", 0.2),
                text_font: Font::Atkinson,
                text: c("#16151c", "#f1f1f6", 0.0),
                text_size: 1.0,
                text_weight: 400.0,
                accent: c("#000000", "#ffffff", 0.65),
                heading_font: Font::JetBrainsMono,
                heading: c("#16151c", "#f1f1f6", 0.0),
                heading_size: 1.0,
                heading_weight: 700.0,
                mark: HeadingMark::None,
                label_case: LabelCase::Upper,
                panel: c("#c4c2d6", "#2b2942", 0.0),
                card_top: c("#bdbbcf", "#36344b", 1.0),
                card_bottom: c("#bdbbcf", "#36344b", 1.0),
                grad_pos: 0.5,
                grad_spread: 1.0,
                panel_blur: 0.0,
                radius: 0.0,
                spacing: 0.85,
                slant: 0.0,
                icon_round: 0.0,
                shadow: c("#14123c73", "#000000cf", 0.0),
                shadow_blur: 0.0,
                shadow_distance: 5.0,
                shadow_angle: 45.0,
                outline: c("#14122a", "#05040e", 0.0),
                outline_width: 1.0,
            },
            Theme {
                id: "memphis",
                name: "Memphis",
                pattern: Pattern::Shapes,
                bg1: c("#f5eedf", "#1b1a20", 0.08),
                bg2: c("#e0d6c1", "#33313a", 0.12),
                text_font: Font::DmSans,
                text: c("#16151c", "#f1f1f6", 0.0),
                text_size: 1.0,
                text_weight: 400.0,
                accent: c("#000000", "#ffffff", 0.65),
                heading_font: Font::DmSans,
                heading: c("#16151c", "#f1f1f6", 0.0),
                heading_size: 1.0,
                heading_weight: 900.0,
                mark: HeadingMark::None,
                label_case: LabelCase::Upper,
                panel: c("#fffdf7", "#26242c", 0.0),
                card_top: c("#f5f3ef", "#312f37", 0.5),
                card_bottom: c("#f5f3ef", "#312f37", 0.5),
                grad_pos: 0.5,
                grad_spread: 1.0,
                panel_blur: 0.0,
                radius: 14.0,
                spacing: 1.0,
                slant: 0.0,
                icon_round: 1.0,
                shadow: c("#16151c", "#f1f1f6", 0.0),
                shadow_blur: 0.0,
                shadow_distance: 5.0,
                shadow_angle: 45.0,
                outline: c("#16151c", "#f1f1f6", 0.0),
                outline_width: 2.5,
            },
            Theme {
                id: "slate",
                name: "Slate",
                pattern: Pattern::Flat,
                bg1: c("#f2f2f2", "#0f0f0f", 0.06),
                bg2: c("#d8d8d8", "#262626", 0.1),
                text_font: Font::Lexend,
                text: c("#16151c", "#f1f1f6", 0.0),
                text_size: 1.0,
                text_weight: 400.0,
                accent: c("#000000", "#ffffff", 0.65),
                heading_font: Font::Lexend,
                heading: c("#16151c", "#f1f1f6", 0.0),
                heading_size: 1.3,
                heading_weight: 300.0,
                mark: HeadingMark::None,
                label_case: LabelCase::Lower,
                panel: c("#ffffff00", "#1d1d1d00", 0.0),
                card_top: c("#ffffff", "#1d1d1d", 1.0),
                card_bottom: c("#ffffff", "#1d1d1d", 1.0),
                grad_pos: 0.5,
                grad_spread: 1.0,
                panel_blur: 0.0,
                radius: 0.0,
                spacing: 1.0,
                slant: 0.0,
                icon_round: 0.0,
                shadow: c("#00000000", "#00000000", 0.0),
                shadow_blur: 0.0,
                shadow_distance: 0.0,
                shadow_angle: 90.0,
                outline: c("#16151c", "#f1f1f6", 0.0),
                outline_width: 0.0,
            },
            Theme {
                id: "velocity",
                name: "Velocity",
                pattern: Pattern::Lines,
                bg1: c("#fbfbfc", "#222228", 0.04),
                bg2: c("#e0e0e4", "#3a3a42", 0.06),
                text_font: Font::Nunito,
                text: c("#16151c", "#f1f1f6", 0.0),
                text_size: 1.0,
                text_weight: 400.0,
                accent: c("#000000", "#ffffff", 0.65),
                heading_font: Font::Nunito,
                heading: c("#16151c", "#f1f1f6", 0.0),
                heading_size: 1.0,
                heading_weight: 800.0,
                mark: HeadingMark::Slash,
                label_case: LabelCase::Upper,
                panel: c("#ffffff", "#2b2b33", 0.0),
                card_top: c("#f5f5f7", "#36363d", 0.1),
                card_bottom: c("#f5f5f7", "#36363d", 0.18),
                grad_pos: 0.5,
                grad_spread: 1.0,
                panel_blur: 0.0,
                radius: 12.0,
                spacing: 1.0,
                slant: 12.0,
                icon_round: 1.0,
                shadow: c("#1e1e3238", "#00000065", 0.0),
                shadow_blur: 20.0,
                shadow_distance: 6.0,
                shadow_angle: 90.0,
                outline: c("#16151c", "#f1f1f6", 0.0),
                outline_width: 0.0,
            },

        ]
    }

    /// The built-in theme with this id, else the default.
    pub fn named(id: Option<&str>) -> Theme {
        let mut all = Theme::defaults();
        let i = all.iter().position(|t| Some(t.id) == id).or_else(|| all.iter().position(|t| t.id == DEFAULT)).unwrap_or(0);
        all.swap_remove(i)
    }
}

/// The colour a screen without one of its own uses (notes/theming.md: a soft grey).
pub fn neutral() -> Color {
    hex("#8b90a0")
}

/// Parses `#rrggbb` (any CSS colour), opaque and clamped into sRGB: a content colour comes from
/// synced data and must not make the background or accent transparent or out of range. `None`
/// when it is not one.
pub fn parse(s: &str) -> Option<Color> {
    let [r, g, b, _] = parse_color(s).ok()?.to_alpha_color::<Srgb>().components;
    if ![r, g, b].iter().all(|x| x.is_finite()) {
        return None;
    }
    Some(Color::new([r.clamp(0.0, 1.0), g.clamp(0.0, 1.0), b.clamp(0.0, 1.0), 1.0]))
}

/// `a` mixed toward `b` by `t` (0: `a`, 1: `b`; NaN: `a`), in Oklab, alpha too, clamped into
/// sRGB (an Oklab line between two sRGB colours can leave it).
pub fn mix(a: Color, b: Color, t: f64) -> Color {
    let t = if t.is_nan() { 0.0 } else { t.clamp(0.0, 1.0) as f32 };
    let (a, b): (AlphaColor<Oklab>, AlphaColor<Oklab>) = (a.convert(), b.convert());
    srgb(a.lerp_rect(b, t))
}

/// `c` in sRGB, clamped into its gamut.
fn srgb(c: AlphaColor<Oklab>) -> Color {
    let c: Color = c.convert();
    Color::new(c.components.map(|x| if x.is_nan() { 0.0 } else { x.clamp(0.0, 1.0) }))
}

/// `c` at alpha `a` times its own.
pub fn fade(c: Color, a: f64) -> Color {
    c.multiply_alpha(if a.is_nan() { 0.0 } else { a.clamp(0.0, 1.0) as f32 })
}

/// `over` painted on opaque `under`.
pub fn over(under: Color, over: Color) -> Color {
    mix(under.with_alpha(1.0), over.with_alpha(1.0), f64::from(over.components[3]))
}

/// How opaque a field's fill is at least (a look parameter, as the theme's own numbers are).
const FIELD_ALPHA: f32 = 0.62;

/// `c`, opaque, with its lightness moved to at least `text`'s distance from `on` on `text`'s side.
/// A colour moved out of sRGB is drawn toward `text` (the same lightness) until it fits.
fn legible(c: Color, text: Color, on: Color) -> Color {
    let mut o: AlphaColor<Oklab> = c.with_alpha(1.0).convert();
    let t: AlphaColor<Oklab> = text.with_alpha(1.0).convert();
    let l = t.components[0];
    if (o.components[0] - l) * (lightness(on) as f32 - l) <= 0.0 {
        return srgb(o);
    }
    o.components[0] = l;
    let fits = |k: f32| {
        let c: Color = o.lerp_rect(t, k).convert();
        c.components[..3].iter().all(|x| (-1e-4..=1.0001).contains(x))
    };
    // the least move toward `text` that fits (bisection to below a colour's f32 precision; `text`
    // itself fits)
    let (mut lo, mut hi) = (0.0_f32, 1.0_f32);
    if !fits(0.0) {
        for _ in 0..20 {
            let m = (lo + hi) / 2.0;
            if fits(m) { hi = m } else { lo = m }
        }
    } else {
        hi = 0.0;
    }
    srgb(o.lerp_rect(t, hi))
}

/// Oklab lightness of `c` (0 black .. 1 white).
pub fn lightness(c: Color) -> f64 {
    let o: AlphaColor<Oklab> = c.convert();
    f64::from(o.components[0])
}

/// A finite `x` clamped to `lo..=hi`, else `or`.
fn num(x: f64, lo: f64, hi: f64, or: f64) -> f64 {
    if x.is_nan() { or } else { x.clamp(lo, hi) }
}

/// A card's colours, resolved in the colour of the thing it stands for.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Card {
    pub top: Color,
    pub bottom: Color,
    /// Text and icons on it.
    pub fg: Color,
    pub muted: Color,
    /// An icon square's fill and glyph.
    pub icon_bg: Color,
    pub icon_fg: Color,
}

/// Everything a widget draws with: one theme in one mode with one main colour, resolved.
#[derive(Clone, Debug, PartialEq)]
pub struct Look {
    pub theme: Theme,
    pub dark: bool,
    /// The screen's contextual colour (the content's, else `neutral()`).
    pub main: Color,
    /// The page: background 1, opaque.
    pub bg: Color,
    /// Background 2: the pattern's decorations.
    pub deco: Color,
    /// A panel's fill (its alpha is panel opacity).
    pub panel: Color,
    /// The panel colour, opaque (menus, the field on home's search).
    pub surface: Color,
    /// Text.
    pub fg: Color,
    /// Secondary text.
    pub muted: Color,
    /// Titles, the brand, section labels.
    pub heading: Color,
    /// Links.
    pub accent: Color,
    /// The caret and the selection handles: the accent, as far in lightness from a field's
    /// background as the text is, at least, so it reads as well as the text.
    pub caret: Color,
    pub outline: Color,
    pub shadow: Color,
    /// Text selection.
    pub selection: Color,
}

impl Look {
    pub fn new(theme: &Theme, dark: bool, main: Option<Color>) -> Look {
        let main = main.unwrap_or_else(neutral);
        let t = theme;
        let fg = t.text.of(dark, main);
        let panel = t.panel.of(dark, main);
        let bg = t.bg1.of(dark, main).with_alpha(1.0);
        let accent = t.accent.of(dark, main);
        let field = over(bg, panel.with_alpha(panel.components[3].max(FIELD_ALPHA)));
        Look {
            theme: theme.clone(),
            dark,
            main,
            bg,
            deco: t.bg2.of(dark, main),
            panel,
            surface: panel.with_alpha(1.0),
            fg,
            muted: fade(fg, 0.58),
            heading: t.heading.of(dark, main),
            accent,
            caret: legible(accent, fg, field),
            outline: t.outline.of(dark, main),
            shadow: t.shadow.of(dark, main),
            selection: fade(main, 0.45),
        }
    }

    /// `px` scaled by the theme's spacing.
    pub fn sp(&self, px: f64) -> f64 {
        px * num(self.theme.spacing, 0.0, 10.0, 1.0)
    }

    /// A running-text size of `px` at the theme's text size.
    pub fn text_px(&self, px: f64) -> f32 {
        (px * num(self.theme.text_size, 0.25, 4.0, 1.0)) as f32
    }

    /// A heading size of `px` at the theme's heading size.
    pub fn heading_px(&self, px: f64) -> f32 {
        (px * num(self.theme.heading_size, 0.25, 4.0, 1.0)) as f32
    }

    pub fn text_weight(&self) -> f32 {
        num(self.theme.text_weight, 100.0, 900.0, 400.0) as f32
    }

    /// Names (tiles, chips): text a step bolder.
    pub fn name_weight(&self) -> f32 {
        (self.text_weight() + 220.0).min(900.0)
    }

    pub fn heading_weight(&self) -> f32 {
        num(self.theme.heading_weight, 100.0, 900.0, 700.0) as f32
    }

    /// Panel opacity: the panel colour's alpha.
    pub fn panel_opacity(&self) -> f64 {
        f64::from(self.panel.components[3])
    }

    /// A field's fill: the panel colour, at least `FIELD_ALPHA` opaque so it shows on see-through
    /// panels.
    pub fn field(&self) -> Color {
        self.panel.with_alpha(self.panel.components[3].max(FIELD_ALPHA))
    }

    /// Whether text on cards is white (card bottom takes more than about half of its colour).
    pub fn on_card_white(&self) -> bool {
        self.theme.card_bottom.dynamic > 0.55
    }

    /// The colours of a card standing for a thing of colour `tint` (`None`: the screen's).
    pub fn card(&self, tint: Option<Color>) -> Card {
        let mut ctx = tint.unwrap_or(self.main);
        let white = self.on_card_white();
        if white {
            // white text needs a dark enough card: a pale tag colour (synced, any colour) is
            // darkened to at most this lightness
            let mut o: AlphaColor<Oklab> = ctx.convert();
            o.components[0] = o.components[0].min(0.62);
            ctx = srgb(o);
        }
        let (t, d) = (&self.theme, self.dark);
        let fg = t.text.of(d, ctx);
        let (fg, muted) = if white { (Color::WHITE, fade(Color::WHITE, 0.82)) } else { (fg, fade(fg, 0.58)) };
        let icon_bg = if white { fade(Color::WHITE, 0.22) } else { ctx };
        Card { top: t.card_top.of(d, ctx), bottom: t.card_bottom.of(d, ctx), fg, muted, icon_bg, icon_fg: Color::WHITE }
    }

    /// Where a card's gradient starts and ends (fractions of its height, may leave 0..1).
    pub fn card_stops(&self) -> (f64, f64) {
        let p = num(self.theme.grad_pos, 0.0, 1.0, 0.5);
        let s = num(self.theme.grad_spread, 0.0, 1.0, 1.0) / 2.0;
        (p - s, p + s)
    }

    /// Shadow offset (dx, dy) at `scale` of the theme's distance.
    pub fn shadow_offset(&self, scale: f64) -> (f64, f64) {
        let a = num(self.theme.shadow_angle, -1e6, 1e6, 90.0).to_radians();
        let d = num(self.theme.shadow_distance, 0.0, 1e4, 0.0) * scale;
        (a.cos() * d, a.sin() * d)
    }

    /// Shadow softness (px) at `scale`.
    pub fn shadow_blur(&self, scale: f64) -> f64 {
        num(self.theme.shadow_blur, 0.0, 1e4, 0.0) * scale
    }

    pub fn outline_width(&self) -> f64 {
        num(self.theme.outline_width, 0.0, 100.0, 0.0)
    }

    pub fn radius(&self) -> f64 {
        num(self.theme.radius, 0.0, 1e4, 0.0)
    }

    /// The slant's shear (tan of the angle).
    pub fn shear(&self) -> f64 {
        num(self.theme.slant, -60.0, 60.0, 0.0).to_radians().tan()
    }

    pub fn icon_round(&self) -> f64 {
        num(self.theme.icon_round, 0.0, 1.0, 1.0)
    }

    /// An icon background's shear: full slant up to roundness .75, none at 1 (a leaning circle
    /// reads as a squashed one).
    pub fn icon_shear(&self) -> f64 {
        self.shear() * ((1.0 - self.icon_round()) * 4.0).clamp(0.0, 1.0)
    }
}
