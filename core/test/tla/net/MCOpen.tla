---- MODULE MCOpen ----
EXTENDS NetOpen
\* rk: a reader r and a store k granted later; Adv m an account member, removed, then a rotation.
RKM == {"r", "k", "m"}
RoleRK == [n \in {"r", "k"} |-> IF n = "r" THEN "reader" ELSE "store"]
MemRK == {"r", "m"}
EvRK == << [op |-> "grant", n |-> "k"], [op |-> "rm", n |-> "m"], [op |-> "rot", n |-> "-"] >>
\* kk: two stores; Adv m an account member, removed, then a rotation.
KKM == {"k1", "k2", "m"}
RoleKK == [n \in {"k1", "k2"} |-> "store"]
MemKK == {"k1", "k2", "m"}
EvRm == << [op |-> "rm", n |-> "m"], [op |-> "rot", n |-> "-"] >>
\* rx: a reader r and a link holder x; Adv m holds a link key, removed, then a rotation.
RXM == {"r", "x", "m"}
RoleRX == [n \in {"r", "x"} |-> IF n = "r" THEN "reader" ELSE "link"]
MemRX == {"r", "x", "m"}
\* pub: a reader and a store; Adv m never a member (holds only public values); a rotation.
MemPub == {"r", "k"}
EvRot == << [op |-> "rot", n |-> "-"] >>
AllRejudge == {"J", "sync", "proof", "link"}
====
