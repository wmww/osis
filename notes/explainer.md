# Explainer site
> Summary: docs/explainer is a static, dependency-free slide-deck site explaining osis to engineers; one deck per topic. Update it when a design decision it shows changes.

- Plain HTML/CSS/JS modules, no build. Serve the directory over HTTP (modules do not load from file://), e.g. `python3 -m http.server -d docs/explainer`.
- `app.js`: hash router (`#/` grid, `#/<deck>/<n>`), pager (back/next cross deck boundaries), theme toggle, keys (arrows, Esc, R replays).
- `lib/svg.js`: diagram helpers returning SVG strings (box, arrow, path, packet, device, blob, key, person, pill, check/cross, code, tiles). Colors are role classes (c1/c2 two parties, c3 ok, c4 crypto, bad, blind) mapped to theme tokens in `style.css`; `d` = entrance delay.
- `decks/index.js` sets reading order. A deck is `{id, title, blurb, icon, slides: [{title, stage, text, more?, enter?}]}`.
- Content mirrors notes/ as of 2026-10-16; it describes the design, not shipped code.
