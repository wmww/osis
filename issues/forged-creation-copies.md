# Forged text creation copies join in arrival order
> Summary: Copies of one text element with differing payloads join by the copy order of spec/crdt.md §4.1, but a char is also carried by undeletes (no creation), and the state cannot tell which record a held char came from: a forged creation copy with another `ts` plus an undelete can leave holders reading different chars. Maps are fixed (entries keyed by (dot, key), spec/crdt.md §5.6) but for a transient expiry residue.
> Tags: security, crdt

## Problem
- Text: an undelete repeats the char (§5.7) with no creation, and joins as a copy of whatever creation is held. With two creations of one dot under different `ts` (only a forged copy), the char goes with the greater creation, so an undelete char folded into the lesser one is dropped when the greater arrives, but kept (maxed) when the greater was there first. Repro: `tests_review::repro_forged_creation_ts_undelete_char` (ignored). Taking the max char over all copies instead fails when a reset prunes the lesser creation (and its char) before the greater arrives.
- Honest copies always carry one char per dot, so only a writer forging a creation copy (snapshot), or a char in its own undelete, can cause it; readers write nothing. Equal-`ts` creation copies with a differing undelete char are order-free (all chars of one creation stamp max).
- Map residue (transient): a dot under two keys (forged), one removed. Value erasure folds both into the key-erased record, whose reset then prunes the other key's record too, so a node before the creation's `T` (or before it sees the purge) holding a post-erasure snapshot beside the valued records reads that key gone, while one without the snapshot reads it live, until it erases too. Repro: `tests_review::repro_forged_key_hidden_by_erased_reset` (ignored). Converges at `T`; honest dots carry one key.

## Direction
- No simple analogue of map keying for text chars (keying elements by (dot, char) splits the sequence's identity).
- Or engine-level: one designated carrier per dot (least snapshot ID); `copies_outside` detects the conflict between held snapshots and a rebuild resolves it (`strip_forged`).
