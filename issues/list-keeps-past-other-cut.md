# A cut's list keeps a commit whatever its path's other edges gave
> Summary: A write refused by one cut of its path (W removes A from H; Q then writes H through [A]) becomes valid when another cut of the path (X removes Q from A) lists it: roles-model `paths` content, osis-perm `paths` `content.rs` `listed` and notes/a1-spec/permissions.md §5.2 Content all read "a cut of P lists it" as enough (notes/evidence-model-findings.md 26).
> Priority: normal
> Tags: security, perm, roles-model

World: X grants Q write on A; W grants A write on H and removes it at ts 4; Q writes H through [A] at ts 5; X removes Q from A at ts 7 listing Q's write. Every node shows the write valid (roles-model `paths::judge` over everything; held-model under J2 too: both hops were granted write before it, so nothing pends). So any later remover of a writer of A, listing what it received, revives what that writer wrote through a thing A had already lost.

A list exists so a removal does not refuse what its writer had received; it should keep a commit only from its own cut: valid by a cut L's list where the path gave r just before the commit's key with L's edge read as before L, and no other cut of the path ordered after the commit leaves it out (addenda vouch alike). Model first (roles-model `paths`, a hand world plus the story's frontiers), then the walk and A1's §5.2 Content sentence.
