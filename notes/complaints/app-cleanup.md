# app-cleanup
> Summary: Footguns met while trimming osis-app and osis-kit.

- `Facet::universal` and `applies` overrides on claim-less facets were dead (opener counts only claimed aspects); `rg` the one call site of a trait method before trusting it matters.
- Production functions used only by tests (`event_time::week`, `event_time::span`) hide among real API: a "used outside tests?" check (rg excluding tests/) finds them faster than reading.
- The duplicate-window scan from kit-cleanup again found most merges; still worth a tiny script in tools/.
