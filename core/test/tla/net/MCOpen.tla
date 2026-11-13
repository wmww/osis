---- MODULE MCOpen ----
EXTENDS NetOpen
\* a reader, a store and the adversary; two stores and the adversary
RKM == {"r", "k", "m"}
RoleRK == [n \in {"r", "k"} |-> IF n = "r" THEN "reader" ELSE "store"]
KKM == {"k1", "k2", "m"}
RoleKK == [n \in {"k1", "k2"} |-> "store"]
====
