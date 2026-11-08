# A text flag below its creation splits reads
> Summary: spec/crdt.md §5.7 lets a node drop a text creation's char once any flag write is held, with a stated limit: a flag stamped below its creation, pruned by a reset that leaves the creation, shows the char only where it was kept. Honest writers can't reach it, but one forged flag (or a forged later creation copy) makes honest nodes read differently forever. Reading the char as one register by stamp closes it.
> Priority: normal
> Tags: crdt, security

**Repro** (osis-crdt, by hand): X creates 'a' at t5; a forged delete at t2; a reset at t3. A node holding X's body reads "a"; one booted from a snapshot taken before the reset (a deleted char is never on the wire) reads absent. No later data repairs it.

**Honest writers can't reach it**: a delete or undelete names an element its writer holds, so by HLC it stamps above the creation (spec/crdt.md §2.2 Next stamp), and an element created and deleted in one commit is left out of the delta (§4.5). Only a forged low `ts`, or a forged copy of the creation at a higher `ts` (§5.7 Join keeps the greater), reaches it.

**Fix**: the char is one LWW register over the creation (its char), deletes (no value) and undeletes (their char); its winner by stamp shows, a value-less winner reads absent (§4.7). A flag below the creation loses to it. The freedom becomes "drop the creation's char once a flag write above it is held": any reset that prunes that flag prunes the creation too, so the limit goes. Touches `SeqElem::char` (osis-crdt, crdt-model), held-model `text_char`, the snapshot rule for which chars ride a run (§3.2 Content), `drop_local_chars`, spec §5.7 State and Live.
