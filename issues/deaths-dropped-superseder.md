# A body arriving after a residue went may die later
> Summary: Dropped bodies keep their writes value-less as residues (`retention/deaths.rs`) only while a held bounded body sorts at or before them, so a body arriving later, older than every held bounded body, can die later than at a node that held it before the drop (never earlier); keeping residues forever would be exact.
> Tags: retention, node, owner-call

Repro: none pinned (needs a lagging writer's body older than everything held under a bounded keep, arriving after a superseder's body dropped and its residue went).

Fixed: deaths are a function of the applied set while the residue lives (retention.rs `deaths_alike_after_*`; the order harness compares every order with a whole replay). A residue W dates only writes with a lower stamp, so it is dropped once no held bounded body sorts at or before it. A body V arriving after that, with W its earliest superseder, dies at a later superseder (bounded by what superseded W): kept longer, under keep at most past its bound by up to that gap. A store from an earlier build has no residues for bodies it already dropped (same effect, plus their live writes come from the state as before).

Owner question: keep residues forever (exact; a few bytes per dropped write, growth like tombstones, spec/requirements.md Scale; keeps the timing of every erased write under keep at most) or accept the window above (current)?
