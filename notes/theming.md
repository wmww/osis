# Theming
> Summary: The app's theming system (Tess's direction, a first draft that will change before stability): a theme is a fixed set of parameters (colours, sliders, a few enums) that every platform implements once; enough knobs for very different designs, harder to get wrong than CSS but not foolproof. No CSS, no per-theme code. Parameter list and design rules.

## Goals (Tess)
- **Diverse**: the knobs reach designs as different as the six defaults (Clarity, Glass, Project, Memphis, Slate, Velocity), and users can make equally distinct themes of their own. The defaults are only defaults.
- **Implementable everywhere**: every value of every parameter is implemented once per platform or widget set (the kit's Masonry widgets, a later web build, anything else). Each must be practical to draw with plain 2D primitives (fills, gradients, rounded rects, skews, shadows, masks, an optional backdrop blur) and must not depend on how a particular widget is built.
- **Hard to get wrong, not impossible**: no arbitrary CSS, which ties themes to one implementation's structure and breaks layouts easily. Parameters can still make a bad theme (white text on white, a zero alpha where it matters); nothing guards against that (Tess).
- Light and dark are not separate themes: one theme gives both, and mode (light, dark, auto) is a user setting outside the theme. Other user settings stay out too: there is no blur switch, panelBlur 0 is the cheap theme.
- Themes are data: stored in osis as a thing (sync, sharing) once built.

## Design rules
- **A contextual colour from the content**: the open thing's colour (else the first among what it holds or links, else a soft grey); inside a sub-view that stands for a thing with a colour of its own (a tile, chip, avatar), that thing's colour. A theme has no main colour of its own; each theme colour's dynamic says how much of the contextual colour mixes in, so card top/bottom dynamic is how strongly a tile takes its thing's colour.
- **Backgrounds**: patterns use only background 1 and background 2 (at varying opacity, no derived shades), so what a theme picks is all there is: background 2 darker gives dark decorations, lighter gives light ones. Sky fades from background 2 at the top to background 1. Placement comes from seeds hashed from the open thing's tid plus a per-kind value, so each thing keeps its own arrangement.
- **Text on cards**: turns white once card bottom's dynamic passes about half.
- **Outlines only where they frame**: panels and fields; cards (tiles, chips, the selection) have none.
- **Things that must agree share one knob**: tiles, the selected sidebar row and chips share the card colours; cards, hover, selection, placeholder and search fields share slant; panel outline and shadow fade with the panel colour's alpha (panel opacity).
- **One knob, one job**: label case and mark are separate enums rather than one bundle.
- **Little motion**: only unobtrusive fades or motion that adds clarity (the main colour fades between things; nothing slides or bounces).
- **Fonts are shippable**: every font except the platform's system font is OFL and good for everyday app use (Tess: freely licensed, with variety).

## Parameters
Enums unless noted. Grouped as the mockup editor shows them (the grouping is editor-only), most important first.
- Colours: each is { light, dark, dynamic }: light and dark are RGBA, picked by mode (none derived from another across modes); dynamic (0..1) is how much the main colour mixes in (oklab, the theme's alpha kept).

Background
- pattern flat|field|curves|sky|grid|dots|shapes|lines|beams|grass: one per theme (Tess: simpler beats layering), placed by four seeds from the open thing's tid plus a small per-kind value (calendar, note, ...). lines: two or three, seeded widths, spacing and angle; beams: light through water from above; grass: blade shapes from the bottom, not a picture.
- background 1 (colour): the page; alpha ignored, nothing is behind it. background 2 (colour): decorations.

Text
- font system (the platform's, not shipped) | inter | dm-sans | figtree | lexend | atkinson (Atkinson Hyperlegible Next) | nunito | literata (serif) | jetbrains-mono. Text and heading pick theirs independently.
- colour (muted text is a fade of it), size (a factor on every text size), weight (100..900; names are text a step bolder).
- links (colour).

Heading (titles, the brand, the calendar's day numbers)
- font, colour, size (a factor), weight (100..900), as for text.
- Section labels and meta headings use the heading's font, colour, size and weight. label case none|upper|lower.
- mark none|underline (titles)|slash (a bar leaning with slant, upright at 0)|dot, all in the main colour; slash and dot go before section labels and before titles with nothing else there (no icon or avatar), dot also after the brand.

Surfaces
- panel (colour; panels are flat, its alpha is panel opacity).
- card top, card bottom (colours): cards (tiles, the selected sidebar row, chips) run top to bottom between them, each in its own thing's context. Fields stand for no thing: the panel colour, at least 62% opaque.
- gradient position (0 top .. 1 bottom: where the change from top to bottom is centred) and spread (0..1 of the height; 0 is a hard line). Equal colours give a flat card, spread 1 a soft gradient, spread 0 a hard gloss line; Glass uses a light top and a near-solid bottom at spread 0.4 for a soft gel. No bevel, no separate highlight.
- panelBlur (px).
Shape
- radius (px), spacing (0..1.5, a factor on every padding, gap and margin; 0 packs everything edge to edge), slant (deg; cards, fields, icon backgrounds and the slash mark lean, text and glyphs stay upright; icons lean less as roundness goes from .75 to 1, none when round), iconRound (0 square .. 1 circle).
Shadow
- colour (its alpha is shadow opacity), softness, distance, angle (a hard Memphis shadow is softness 0); panels scale their shadow.
Outline
- colour, width (px).

## Implementations
- app/mockup (reference): themes.js lists the parameters (THEME_SECTIONS) and the six defaults; engine.css implements every value once over the layout in style.css; the switcher's editor edits any parameter (a built-in forks into a custom theme).
- kit: libs/kit/src/theme.rs `Theme` (the same parameters and six defaults, values copied from themes.js), resolved into a `Look` for the screen's colour; `Look::card(tint)` resolves a card in the colour of the thing it stands for. Backgrounds in backdrop.rs, marks in widgets/mark.rs. Gaps: no panelBlur (Vello has no backdrop blur; a blurring panel gets only the faint lit top edge), beams drawn without blur, the underline mark drawn in the title's own colour (a Masonry text area paints with one brush), the home brand and labels on Sky stay heading-coloured (the mockup whitens them), no custom themes or parameter editor in the app. Change themes.js and theme.rs together.
