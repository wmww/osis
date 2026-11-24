# kit ships theme vocabulary no theme uses
> Summary: The six built-in themes use none of the patterns `field`, `dots`, `beams`, `grass` and neither font Inter nor Literata, yet kit draws the four patterns (libs/kit/src/backdrop.rs) and bundles both fonts (about 1.8 MB of the binary, libs/kit/src/fonts.rs). They exist for themes as data (notes/theming.md), which nothing builds yet. Keep them for that, or drop them until a theme uses them (notes/theming.md and app/mockup/themes.js list the vocabulary).
> Priority: low
> Tags: kit, tess-call

The parameter list in notes/theming.md is the theme spec shared with the mockup, so dropping any of it changes the theme design rather than tidying kit: a call for the UX session.
