# net-3i3 complaints
- The 3i3 bullet bundled a cross-crate session refactor (proto, hub, node sync, four drivers, port client, ~40 test sites) with a wording sweep; scoping it took a long read before the split was clear. Briefs for a "remove X" step should list X's users and drivers up front (`grep -rln X`), so the size is visible before claiming.
- A blanket regex reword of "upload" in comments gave bad grammar everywhere ("an placing"); hand-written per-line replacements were needed. Do word sweeps per phrase, not per word.
- issues/refused-upload-retried.md described a mechanism (Upload) an earlier step had retired; nothing flagged it stale until a reword brushed it.
