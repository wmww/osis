---- MODULE MCOpen ----
EXTENDS NetOpen
\* rk: a reader r and a store k granted later; Adv m a holder, removed (a rotation), then a rotation.
RKM == {"r", "k", "m"}
RoleRK == [n \in {"r", "k"} |-> IF n = "r" THEN "reader" ELSE "store"]
MemRK == {"r", "m"}
EvRK == << [op |-> "grant", n |-> "k"], [op |-> "rm", n |-> "m"], [op |-> "rot", n |-> "-"] >>
\* kk: two stores; Adv m a holder, removed, then a rotation.
KKM == {"k1", "k2", "m"}
RoleKK == [n \in {"k1", "k2"} |-> "store"]
MemKK == {"k1", "k2", "m"}
EvRm == << [op |-> "rm", n |-> "m"], [op |-> "rot", n |-> "-"] >>
\* pub: a reader and a store; Adv m never a holder; a rotation.
MemPub == {"r", "k"}
EvRot == << [op |-> "rot", n |-> "-"] >>
====
