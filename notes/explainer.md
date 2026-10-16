# Explainer site
> Summary: docs/explainer is a static, dependency-free slide-deck site explaining osis to engineers; one deck per topic. Update it when a design decision it shows changes.

- Plain HTML/CSS/JS modules, no build. Serve the directory over HTTP (modules do not load from file://), e.g. `python3 -m http.server -d docs/explainer`.
- `app.js`: hash router (`#/` grid, `#/<deck>/<n>`), theme toggle, view-mode toggle (remembered):
  - slides: one slide, pager (back/next cross deck boundaries), keys (arrows, Esc, R replays); `fit()` caps the diagram height (`--fit` on `.stage`) so the slide fits above the pager.
  - page: whole deck on one scrolling page; slides stay `.idle` (animations paused, SMIL paused) until scrolled into view; the hash follows the slide being read via `replaceState`.
- `mount()` crops static diagrams' viewBox to content (vertical only, so text scale stays uniform) and replaces marker arrowheads on drawn-in paths with separate heads that fade in as the line arrives (`arrowheads`). Demos that re-render (`.demo`) call these helpers themselves.
- `lib/svg.js`: diagram helpers returning SVG strings (box, arrow, path, packet, device, blob, key, person, pill, check/cross, code, tiles). Colors are role classes (c1/c2 two parties, c3 ok, c4 crypto, bad, blind) mapped to theme tokens in `style.css`; `d` = entrance delay.
- `decks/index.js` sets reading order. A deck is `{id, title, blurb, icon, slides: [{title, stage, text, more?, enter?}]}`.
- Content describes the design, not shipped code. It predates the split into spec/ and notes/; check it against spec/ when next updated.
