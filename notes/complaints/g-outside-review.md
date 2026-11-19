# g-outside-review
- `wt claim g-outside` reused a stale local branch from an earlier pre-rebase copy of the work (not an ancestor of the remote branch); reset to origin/windlass-g-outside by hand.
- Two doc comments landed on the wrong item (a new fn inserted between an old fn's doc and its body: `atomic::applied_late`, `pending::take_parts`); clippy does not see it.
- A thing cannot be minted without a strong in its unit at the maker (`NotHeld`), so "minting commit held, strong in a later commit" exists only for a strong part missing, waiting or invalid at the receiver: briefs posing that case should say so.
- Item-7-style questions (why a thing is outside a closure) have no explain: `why_kept` says why kept, never why not entered; a probe printing `ActorEpochs` was needed.
