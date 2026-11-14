# Test anchors outside the sync spec name no rule
> Summary: `spec_map.py --gaps` checks test anchors only in spec/sync*.md and spec/wire.md (ANCHOR_CHECKED); 346 citations of permissions, crypto, commits, crdt, data-model and versioning name no text of their section.
> Priority: low
> Tags: tests

A test cites a rule as `spec/<file>.md §N (anchor)`; in ANCHOR_CHECKED files the anchor must be a RULES anchor of §N or `;`-separated names (each optionally `name: gloss`) found in §N's text (tools/spec_map.py `stray_anchors`). Elsewhere anchors are free text, so a moved or reworded rule orphans its tests silently. Fix: repoint those citations (as the sync ones were), then widen ANCHOR_CHECKED to `spec/`. Count them by setting ANCHOR_CHECKED to `("spec/",)`.
