# A witness's leaving out walks per candidate at every change of its component
> Summary: In a fight (a candidate R does not apply with), a witness siding with R re-runs the leaving out at every change of R's component: one walk from scratch per candidate, k of them chosen by the removed party, so each write there costs about k walks at every such witness, for as long as R is held.
> Priority: normal
> Tags: engine, perm, security

`flows/vouches.rs` `owed`: a left-out candidate (X's lowering of the remover, say) stays uncounted and one the witness could write, so `owes(&all)` holds at every judgement; `leaving_out` then finds R does not stand with all listed (`Timeline::stands_with`, a walk from scratch with R trusted) and walks once more per candidate, only to write nothing. The removal is filed under its component (`vouch_watch`), so every change of that component judges it again.

Measured (debug, `osis_perm::commits_walked` for one grant on t at W after W sided with R and vouched; X made k more role writes on t that W received before R, and one demotion of R's author): k = 2: 209 commits walked (38 with vouch writing off); k = 20: 4,277 (182 off). The component already walks from scratch per update (it holds a trust set); the flow multiplies that by about k + 2.

Who controls k: the removed party, by role writes received before R's `ts` (made while it still held the right; a thief's before the theft was noticed). Only witnesses siding with R pay, and only while some candidate makes R not stand.

Wanted: the leaving out judged once per input it reads (R, the candidates, the trust set) rather than per component change, with a rule for when a walk change may un-leave a candidate (spec/permissions.md §5.1 Vouches, Writing reads "its own current first walk"); or a leaving out in fewer walks. A test counting walks per write at k and 10k.
