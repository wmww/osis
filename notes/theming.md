# Theming
> Summary: The app's theming system (Tess's direction, a first draft that will change before stability): a theme is a fixed set of parameters (colours, sliders, a few enums) that every platform implements once; enough knobs for very different designs, constrained so every combination is somewhere between excellent and a bit ugly, never unusable or broken. No CSS, no per-theme code. Parameter list and the rules that keep combinations safe.

## Goals (Tess)
- **Diverse**: the knobs reach designs as different as the six defaults (Frost, Glass, Workstation, Memphis, Slate, Cel), and users can make equally distinct themes of their own. The defaults are only defaults.
- **Implementable everywhere**: every value of every parameter is implemented once per platform or widget set (the kit's Masonry widgets, a later web build, anything else). Each must be practical to draw with plain 2D primitives (fills, gradients, rounded rects, skews, shadows, masks, an optional backdrop blur) and must not depend on how a particular widget is built.
- **Never broken**: almost every combination lands between excellent and a bit ugly; none is unusable (unreadable text, invisible controls, broken layout). This is why there is no arbitrary CSS: it can do anything, including break the UI, and it ties themes to one implementation's structure.
- Light and dark are not separate themes: one theme gives both, and mode (light, dark, auto) is a user setting outside the theme. Other user settings stay out too: there is no blur switch, panelBlur 0 is the cheap theme.
- Themes are data: stored in osis as a thing (sync, sharing) once built.

## Rules that keep combinations safe
- **One main colour from the content**: the open thing's colour, else the first among what it holds or links, else a soft grey. A theme has no main colour of its own; accents, selection and background tint derive from it.
- **The background is shades of one colour**: bgTint mixes the main colour into the whole background (0: none); every decoration is a lighter or darker shade of the result, never separately tinted, so none fights the content or vanishes at tint 0. Placement comes from seeds hashed from the open thing's tid plus a per-kind value, so each thing keeps its own arrangement.
- **Derived contrast**: text on a card turns white once its fill passes about half; cards always keep a trace of their colour and step away from an opaque panel's surface, so they never blend in. Dark mode strengthens shadows.
- **Weights move headings only**: body text keeps the accent's weight, so a heavy or light theme stays readable.
- **Outlines only where they frame**: panels and fields; cards (tiles, chips, the selection) have none.
- **Things that must agree share one knob**: tiles and the selected sidebar row share fill; cards, hover, selection, placeholder and search fields share slant; panel outline and shadow fade with panel opacity.
- **Packages instead of free combinations** where free ones clash: the accent bundles label style, per-role base weights and marks.
- **Little motion**: only unobtrusive fades or motion that adds clarity (the main colour fades between things; nothing slides or bounces).
- **Fonts are shippable**: every font except the platform's system font is OFL and good for everyday app use (Tess: freely licensed, with variety).

## Parameters
Enums unless noted.
- Colours, each a light and dark pair: background, surface, outline, shadow (none derived from another across modes).
- bgTint (0..1).
- background flat|field|curves|sky|grid|dots|shapes|lines|beams|grass: one per theme (Tess: simpler beats layering), placed by four seeds from the open thing's tid plus a small per-kind value (calendar, note, ...). lines: two or three, seeded widths, spacing and angle; beams: light through water from above; grass: blade shapes from the bottom, not a picture.
- panelOpacity (0..1) and panelBlur (px).
- spacing (a factor on every padding, gap and margin), radius (px), iconRound (0 square .. 1 circle), slant (deg; text stays upright).
- outline (px). shadowOpacity, shadowBlur (softness), shadowDistance, shadowAngle (a hard Memphis shadow is softness 0); panels scale their shadow.
- gloss (0..1): a highlight line across fills and a faint lit top edge. No bevel.
- fill (0..1): how much of its colour a card takes; tiles use their own colour, the selected sidebar row the screen's.
- font system (the platform's, not shipped) | inter | dm-sans | figtree | lexend | atkinson (Atkinson Hyperlegible Next) | nunito | literata (serif); JetBrains Mono for mono labels. weight (-1..1): titles most, labels less, names a little.
- accent plain|caps|bar|rule|slash. bar: mono labels, title bars, a stripe on tiles. rule: big light labels, a line atop the pane. slash: caps labels, slashes, underlined titles, a corner flag on tiles.

## Implementations
- app/mockup (reference): themes.js lists the parameters (THEME_PARAMS) and the six defaults; engine.css implements every value once over the layout in style.css; the switcher's editor edits any parameter (a built-in forks into a custom theme).
- kit: libs/kit/src/theme.rs `Theme`, resolved into a `Look`; backgrounds in backdrop.rs (notes/app.md Prototype). No panelBlur (Vello has no backdrop blur), beams drawn as gradient bands without blur, no custom themes or parameter editor in the app.
