# Readers trust a header's aspect list
> Summary: `index_commit` indexes every aspect a header lists, held part or not, and some readers take index presence as fact (`flows::is_node`, `labeling::actors` "is a node"). Since whole-commits step 3 a header-only commit by any author applies with no record or reach check on its things, so a stranger's header listing `(t, node.0)` makes `t` read as a node.
> Tags: security, engine

Probe (whole-3 review): peer 1, with no role on thing `d`, signs a content commit writing `node.0` on `d`; with its parts stripped, peer 2 applies it (`Applied`, aspect invalid) and `ix.by_aspect` holds `(d, node.0)`. On main before step 3 the same header-only commit pended on the author's reach (`waits_whole`). A commit with a held part on another thing indexed an unsynced listed thing's aspect already before step 3 (`gating` skipped unsynced things), so the hole is older; step 3 removes the need for any held part.

Readers keyed on presence: `flows::is_node` (picks `ReaderKey::Dh` over `Static` for a key actor, so a recovery or link key "made a node" gets boxes in the wrong form; `edges::deliver_parts` sends it direct deliveries), `labeling::actors` holders skip. Others read validity (`valid_secrets_part`) or values (`labeled`, `held_links`).

Fix direction: readers that ask "does t have X" read the valid state, not `by_aspect` keys; or index only aspects with a held part. Check every `by_aspect` key-presence reader.
