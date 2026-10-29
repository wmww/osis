//! Themes (notes/theming.md): a theme is a fixed set of parameters, never code. `Theme` holds
//! them, `Theme::defaults` the six built-ins, and `Look::new` resolves a theme, a mode and the
//! screen's main colour into the concrete colours and sizes the kit widgets draw with. Every
//! widget takes its look from a `Look`; changing theme, mode or main colour means a new `Look`.

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

/// A colour per mode.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Pair {
    pub light: Color,
    pub dark: Color,
}

impl Pair {
    pub fn of(&self, dark: bool) -> Color {
        if dark { self.dark } else { self.light }
    }
}

/// What a theme draws behind everything (one per theme).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backdrop {
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

/// Label style, per-role base weights and marks, as one package.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Accent {
    Plain,
    Caps,
    Bar,
    Rule,
    Slash,
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
}

/// A theme's parameters (notes/theming.md Parameters).
#[derive(Clone, Debug, PartialEq)]
pub struct Theme {
    pub id: &'static str,
    pub name: &'static str,
    pub background: Pair,
    pub surface: Pair,
    pub outline_color: Pair,
    pub shadow_color: Pair,
    /// 0..1: how much of the main colour goes into the whole background.
    pub bg_tint: f64,
    pub backdrop: Backdrop,
    /// 0..1.
    pub panel_opacity: f64,
    /// px; unused (no backdrop blur in Vello).
    pub panel_blur: f64,
    /// A factor on every padding, gap and margin.
    pub spacing: f64,
    /// px.
    pub radius: f64,
    /// deg; cards lean, text stays upright.
    pub slant: f64,
    /// 0 square .. 1 circle.
    pub icon_round: f64,
    /// px; panels and fields only.
    pub outline: f64,
    pub shadow_opacity: f64,
    pub shadow_blur: f64,
    pub shadow_distance: f64,
    /// deg, 90 = straight down.
    pub shadow_angle: f64,
    /// 0..1.
    pub gloss: f64,
    /// 0..1: how much of its colour a card takes.
    pub fill: f64,
    pub font: Font,
    /// -1..1: moves heading weights only.
    pub weight: f64,
    pub accent: Accent,
}

fn hex(s: &str) -> Color {
    parse_color(s).map(|c| c.to_alpha_color::<Srgb>()).unwrap_or(Color::from_rgb8(128, 128, 128))
}

fn pair(l: &str, d: &str) -> Pair {
    Pair { light: hex(l), dark: hex(d) }
}

impl Theme {
    /// The six built-in themes (the mockup's themes.js values).
    pub fn defaults() -> Vec<Theme> {
        vec![
            Theme {
                id: "frost",
                name: "Frost",
                background: pair("#f2f3f7", "#0f1117"),
                surface: pair("#ffffff", "#1f2129"),
                outline_color: pair("#16151c", "#f1f1f6"),
                shadow_color: pair("#14203c", "#000000"),
                bg_tint: 0.15,
                backdrop: Backdrop::Curves,
                panel_opacity: 0.0,
                panel_blur: 0.0,
                spacing: 1.1,
                radius: 18.0,
                slant: 0.0,
                icon_round: 1.0,
                outline: 0.0,
                shadow_opacity: 0.3,
                shadow_blur: 18.0,
                shadow_distance: 6.0,
                shadow_angle: 90.0,
                gloss: 0.0,
                fill: 0.08,
                font: Font::System,
                weight: 0.0,
                accent: Accent::Plain,
            },
            Theme {
                id: "glass",
                name: "Glass",
                background: pair("#e6eef8", "#07101e"),
                surface: pair("#ffffff", "#18223a"),
                outline_color: pair("#16151c", "#f1f1f6"),
                shadow_color: pair("#002050", "#000000"),
                bg_tint: 0.55,
                backdrop: Backdrop::Sky,
                panel_opacity: 0.55,
                panel_blur: 24.0,
                spacing: 1.0,
                radius: 14.0,
                slant: 0.0,
                icon_round: 1.0,
                outline: 0.0,
                shadow_opacity: 0.35,
                shadow_blur: 16.0,
                shadow_distance: 7.0,
                shadow_angle: 90.0,
                gloss: 1.0,
                fill: 1.0,
                font: Font::Figtree,
                weight: -0.3,
                accent: Accent::Plain,
            },
            Theme {
                id: "workstation",
                name: "Workstation",
                background: pair("#d4d4e2", "#0d0e18"),
                surface: pair("#c4c2d6", "#2b2942"),
                outline_color: pair("#14122a", "#05040e"),
                shadow_color: pair("#14123c", "#000000"),
                bg_tint: 0.2,
                backdrop: Backdrop::Grid,
                panel_opacity: 1.0,
                panel_blur: 0.0,
                spacing: 0.85,
                radius: 0.0,
                slant: 0.0,
                icon_round: 0.0,
                outline: 1.0,
                shadow_opacity: 0.45,
                shadow_blur: 0.0,
                shadow_distance: 5.0,
                shadow_angle: 45.0,
                gloss: 0.0,
                fill: 1.0,
                font: Font::Atkinson,
                weight: 0.0,
                accent: Accent::Bar,
            },
            Theme {
                id: "memphis",
                name: "Memphis",
                background: pair("#f5eedf", "#1b1a20"),
                surface: pair("#fffdf7", "#26242c"),
                outline_color: pair("#16151c", "#f1f1f6"),
                shadow_color: pair("#16151c", "#f1f1f6"),
                bg_tint: 0.12,
                backdrop: Backdrop::Shapes,
                panel_opacity: 1.0,
                panel_blur: 0.0,
                spacing: 1.0,
                radius: 14.0,
                slant: 0.0,
                icon_round: 1.0,
                outline: 2.5,
                shadow_opacity: 1.0,
                shadow_blur: 0.0,
                shadow_distance: 5.0,
                shadow_angle: 45.0,
                gloss: 0.0,
                fill: 0.5,
                font: Font::DmSans,
                weight: 0.5,
                accent: Accent::Caps,
            },
            Theme {
                id: "slate",
                name: "Slate",
                background: pair("#f2f2f2", "#0f0f0f"),
                surface: pair("#ffffff", "#1d1d1d"),
                outline_color: pair("#16151c", "#f1f1f6"),
                shadow_color: pair("#000000", "#000000"),
                bg_tint: 0.1,
                backdrop: Backdrop::Flat,
                panel_opacity: 0.0,
                panel_blur: 0.0,
                spacing: 1.0,
                radius: 0.0,
                slant: 0.0,
                icon_round: 0.0,
                outline: 0.0,
                shadow_opacity: 0.0,
                shadow_blur: 0.0,
                shadow_distance: 0.0,
                shadow_angle: 90.0,
                gloss: 0.0,
                fill: 1.0,
                font: Font::Lexend,
                weight: 0.0,
                accent: Accent::Rule,
            },
            Theme {
                id: "cel",
                name: "Cel",
                background: pair("#fbfbfc", "#222228"),
                surface: pair("#ffffff", "#2b2b33"),
                outline_color: pair("#16151c", "#f1f1f6"),
                shadow_color: pair("#1e1e32", "#000000"),
                bg_tint: 0.06,
                backdrop: Backdrop::Lines,
                panel_opacity: 1.0,
                panel_blur: 0.0,
                spacing: 1.0,
                radius: 12.0,
                slant: 12.0,
                icon_round: 1.0,
                outline: 0.0,
                shadow_opacity: 0.22,
                shadow_blur: 20.0,
                shadow_distance: 6.0,
                shadow_angle: 90.0,
                gloss: 0.0,
                fill: 0.08,
                font: Font::Nunito,
                weight: 0.0,
                accent: Accent::Slash,
            },
        ]
    }

    /// The built-in theme with this id, else the first.
    pub fn named(id: &str) -> Theme {
        let all = Theme::defaults();
        let i = all.iter().position(|t| t.id == id).unwrap_or(0);
        all.into_iter().nth(i).unwrap_or_else(|| Theme::defaults().swap_remove(0))
    }
}

/// The colour a screen without one of its own uses (notes/theming.md: a soft grey).
pub fn neutral() -> Color {
    hex("#8b90a0")
}

/// Parses `#rrggbb` (any CSS colour); `None` when it is not one.
pub fn parse(s: &str) -> Option<Color> {
    parse_color(s).ok().map(|c| c.to_alpha_color::<Srgb>())
}

/// `a` mixed toward `b` by `t` (0: `a`, 1: `b`), in Oklab, alpha too.
pub fn mix(a: Color, b: Color, t: f64) -> Color {
    let t = t.clamp(0.0, 1.0) as f32;
    let (a, b): (AlphaColor<Oklab>, AlphaColor<Oklab>) = (a.convert(), b.convert());
    let c = a.lerp_rect(b, t);
    c.convert()
}

/// `c` at alpha `a` times its own.
pub fn fade(c: Color, a: f64) -> Color {
    c.multiply_alpha(a.clamp(0.0, 1.0) as f32)
}

/// Oklab lightness of `c` (0 black .. 1 white).
pub fn lightness(c: Color) -> f64 {
    let o: AlphaColor<Oklab> = c.convert();
    f64::from(o.components[0])
}

/// Everything a widget draws with: one theme in one mode with one main colour, resolved.
#[derive(Clone, Debug, PartialEq)]
pub struct Look {
    pub theme: Theme,
    pub dark: bool,
    /// The screen's main colour (the content's, else `neutral()`).
    pub main: Color,
    /// Window background: the theme's, tinted by the main colour.
    pub bg: Color,
    /// A panel's fill (with its opacity applied).
    pub panel: Color,
    /// An opaque surface (fields, menus).
    pub surface: Color,
    /// Text.
    pub fg: Color,
    /// Secondary text.
    pub muted: Color,
    /// Links, focus, selection: the main colour made readable on the background.
    pub accent: Color,
    pub outline: Color,
    pub shadow: Color,
    /// Text selection and the caret.
    pub selection: Color,
}

impl Look {
    pub fn new(theme: &Theme, dark: bool, main: Option<Color>) -> Look {
        let main = main.unwrap_or_else(neutral);
        let base = theme.background.of(dark);
        let bg = mix(base, main, theme.bg_tint);
        let surface = theme.surface.of(dark);
        let panel = fade(surface, theme.panel_opacity);
        let (fg, muted) = if dark { (hex("#ececf1"), hex("#ececf1").multiply_alpha(0.6)) } else { (hex("#16151c"), hex("#16151c").multiply_alpha(0.58)) };
        let accent = if dark { mix(main, Color::WHITE, 0.25) } else { mix(main, Color::BLACK, 0.2) };
        // dark mode strengthens shadows
        let boost = if dark { 1.6 } else { 1.0 };
        let shadow = fade(theme.shadow_color.of(dark), (theme.shadow_opacity * boost).min(1.0));
        Look { theme: theme.clone(), dark, main, bg, panel, surface, fg, muted, accent, outline: theme.outline_color.of(dark), shadow, selection: fade(main, 0.45) }
    }

    /// `px` scaled by the theme's spacing.
    pub fn sp(&self, px: f64) -> f64 {
        px * self.theme.spacing
    }

    /// The fill of a card (tile, chip, selection) of colour `tint` (`None`: neutral).
    pub fn card(&self, tint: Option<Color>) -> Color {
        let tint = tint.unwrap_or_else(neutral);
        // a card on an opaque panel steps away from the panel's surface
        let step = if self.dark { Color::WHITE } else { hex("#3a3f55") };
        let card_surface = mix(self.surface, step, 0.05 * self.theme.panel_opacity);
        let base = fade(card_surface, 0.62 + self.theme.panel_opacity * 0.38);
        let c = mix(base, tint, 0.05 + self.theme.fill * 0.95);
        // composited over the background so a shadow never shows through it
        let a = f64::from(c.components[3]);
        mix(self.bg, c.with_alpha(1.0), a)
    }

    /// Whether text on a card is white (its fill passed about half).
    pub fn on_card_white(&self) -> bool {
        self.theme.fill > 0.55
    }

    /// Text colour on a card.
    pub fn card_fg(&self) -> Color {
        if self.on_card_white() { Color::WHITE } else { self.fg }
    }

    pub fn card_muted(&self) -> Color {
        if self.on_card_white() { Color::WHITE.multiply_alpha(0.82) } else { self.muted }
    }

    /// An icon square's fill on a card of colour `tint`.
    pub fn icon_fill(&self, tint: Option<Color>) -> Color {
        let tint = tint.unwrap_or_else(neutral);
        if self.on_card_white() { Color::WHITE.multiply_alpha(0.22) } else { mix(tint, Color::WHITE, 0.2) }
    }

    /// Shadow offset (dx, dy) at `scale` of the theme's distance.
    pub fn shadow_offset(&self, scale: f64) -> (f64, f64) {
        let a = self.theme.shadow_angle.to_radians();
        let d = self.theme.shadow_distance * scale;
        (a.cos() * d, a.sin() * d)
    }

    /// The heading weight for a role whose base is `base` and that moves `per` per unit of the
    /// theme's weight.
    pub fn weight(&self, base: f64, per: f64, lo: f64, hi: f64) -> f32 {
        (base + self.theme.weight * per).clamp(lo, hi) as f32
    }
}
