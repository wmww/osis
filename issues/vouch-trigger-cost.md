# Removals judged at every update of a second walk's component
> Summary: perm reports a component whose timeline is a second walk (a vouch counts there) as `Changed::evaluated` at every update, so `flows/vouches.rs` gathers again and decides again every removal filed there (one with candidates, or applying as no lowering in the first walk) at each update of it, a removed party's never-applying role commits included; perm should report what changed in each walk instead.
> Priority: normal
> Tags: engine, perm, security

`flows/vouches.rs` keeps each removal's gathering (whether it applies, its candidates) and judges it again only on what it reads (notes/engine-roles.md, Vouches, Write). One trigger is coarse: `note_evaluated`, a component walked anew. perm walks a second walk from scratch whenever the counting entries change, and reports the component evaluated even when the second walk went on by `append` (`incremental.rs`: `if second || c.tl.second()`), because `Changed::commits` diffs only the final walk's history and the vouch flow reads the first walk too (`in_question`, `could_write`).

Cost: in a component where a vouch counts, every role commit arriving (an honest grant, or a removed party's junk commit that applies nowhere) re-gathers each removal filed there: one pass over the in-question parties' role commits before R and the demoted node's commits on each thing, plus the addenda fixpoint. m filed removals cost m gatherings per update of that component. Removals not applying are not affected (their trigger is their own change, which the final-walk diff reports exactly).

Wanted: `Changed` naming the commits whose change differs in the first walk as well as the final one (the first walk's `Appended` is kept on `append`; a second walk dropping back to one needs the old first walk's history), so `note_evaluated` fires only on real re-evaluations (merges, trust changes). Count test: a removal with candidates in a component with a counting vouch, an honest grant elsewhere there, gatherings at n and 10n candidates: 0.

Also for a reviewer: the wake climbs `Held::reach` from a backdated or late commit's author and edge parties (every thing they hold, transitively), not a single chain; it runs only for commits stamped no later than the newest filed removal.
