# theming-mockup
- `python3 -m http.server` sends no cache headers, so a headless browser (and the user's) kept serving stale engine.css/themes.js after edits; screenshots silently showed old code. Route requests with `cache-control: no-cache` in playwright (`page.route`) or hard-refresh.
