# lost-e2e
- A forensic attack on a sync World node costs 250-350 G instructions in debug (three accounts' rows and every unopened S section times every candidate key): the device-attack tests had to go by hand. A cheaper evidence scope (one node's store per sync ID) would make them default tests.
- spec_map anchors must be a RULES anchor verbatim or text of the section: a `: gloss` inside the parenthesis is not split off for RULES anchors, so `§2 (class from the key: ...)` reads as stray. The convention note says a gloss is free; it is only for text-matched names.
- Several rebuilt-sync obligations exist as engine functions nobody calls in production (`ensure_rotated` before encrypting, `joined_links_ended`, `untie` after a pass): grep for callers of each engine `pub fn` the old node sync called would have found them in one pass.
- The coordinator's pointer to origin branch `fork-sides` did not resolve (no such remote ref).
