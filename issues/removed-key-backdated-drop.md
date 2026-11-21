# A removed key's backdated lowering drops honest writes for good
> Summary: In roles-model `paths` (the stated-path walk), a key removed before the theft can backdate a lowering ordered before its own removal: it applies at its key, drops the honest writes resting on the lowered edge, and its own removal then drops it, but drops stand for good (finding 16), so the honest writes stay lost, everyone holding the removal.
> Priority: normal
> Tags: perm, security

**World** (roles-model `src/paths/tests.rs`, `a_removed_keys_backdated_lowering_drops_a_witness_write_for_good`): H paired N5; B shared T1 with A2 at 2; X removed N5 at 3 listing H's grant, everyone received it; H removes X at 6 listing it. With N5's key the thief backdates a removal of B to 2, ordered after B's share. It applies (N5 an admin at 2), drops B's share, and X's removal of N5 drops it; B's share stays dropped. The story reaches it with moves 47, 48 (N5's key lowering B before X's removal of N5) wherever B wrote through its edge before: every failure of the story's searches (`random_worlds_hold_large`, `small_family_holds_large`: liveness, KNOWN in tools/known_failures.txt). Aimed at H instead, the lowering is void (its drops take its own grant).

**Why**: each lowering is judged once and its drops stand (notes/write-path-design.md §1, finding 16); a lowering whose author's edge a later lowering drops keeps its drops. That was accepted for fights among admins; here the author is a removed key and the removal of it was held by everyone.

**Owed**: a rule under which a lowering by a key whose own removal, ordered after it, does not list it drops nothing a reader holds as the removal's evidence; or the class stated as a limit with Tess. Model first (roles-model `paths`).
