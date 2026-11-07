--------------------------------- MODULE MC ---------------------------------
(* Scenarios for SyncConvergence; each .cfg picks one prefix.                *)
EXTENDS SyncConvergence

F(dom, c0, v0, dflt) == [c \in dom |-> IF c = c0 THEN v0 ELSE dflt]

(* N: history `none`: w2's c2 kills d1 of w1's c1; every writer holding c1  *)
(* owes a covering snapshot (s1 by w1, s2 by w2); c1 goes as covered.        *)
N_Commits == {"c1", "c2", "s1", "s2"}
N_Author == [c \in N_Commits |-> IF c \in {"c2", "s2"} THEN "w2" ELSE "w1"]
N_Deps == [c \in N_Commits |-> CASE c = "c1" -> {} [] c = "c2" -> {"c1"} [] OTHER -> {"c2"}]
N_CD == [c \in N_Commits |-> CASE c = "c1" -> {"d1"} [] c = "c2" -> {"d2"} [] c = "s1" -> {"ds1"} [] c = "s2" -> {"ds2"}]
N_Kills == F(N_Commits, "c2", {"d1"}, {})
N_Covers == [c \in N_Commits |-> IF c \in {"s1", "s2"} THEN {"d1", "d2"} ELSE {}]
N_Purges == [c \in N_Commits |-> {}]
N_None == [c \in N_Commits |-> 99]
N_Zero == [c \in N_Commits |-> 0]

(* L: as N with a two-delta body: c2 kills d1 of c1 = {d1, e1}, e1 stays    *)
(* live, carried by the covers (which are `none` too: they carry e1).        *)
L_CD == [c \in N_Commits |-> CASE c = "c1" -> {"d1", "e1"} [] c = "c2" -> {"d2"} [] c = "s1" -> {"ds1"} [] c = "s2" -> {"ds2"}]
L_Covers == [c \in N_Commits |-> IF c \in {"s1", "s2"} THEN {"d1", "e1", "d2"} ELSE {}]

(* P: purge of a reset write inside a two-delta commit (rewrite, strict     *)
(* subset rule), re-snapshot after the purge. No time.                       *)
P_Commits == {"c3", "p", "s"}
P_Author == [c \in P_Commits |-> IF c = "c3" THEN "w1" ELSE "w2"]
P_Deps == [c \in P_Commits |-> CASE c = "c3" -> {} [] c = "p" -> {"c3"} [] c = "s" -> {"p"}]
P_CD == [c \in P_Commits |-> CASE c = "c3" -> {"a", "b"} [] c = "p" -> {"pa"} [] c = "s" -> {"ds"}]
P_Kills == F(P_Commits, "p", {"a"}, {})
P_Covers == F(P_Commits, "s", {"a", "b", "pa"}, {})
P_Purges == F(P_Commits, "p", {"a"}, {})
P_None == [c \in P_Commits |-> 99]
P_Zero == [c \in P_Commits |-> 0]

(* D: a non-writer deposits a commit a writer promotes; an expiring write;  *)
(* a reader relays; the host replays a stale entry.                          *)
D_Commits == {"cr", "c4"}
D_Author == [c \in D_Commits |-> IF c = "cr" THEN "r" ELSE "w1"]
D_Deps == [c \in D_Commits |-> {}]
D_CD == [c \in D_Commits |-> IF c = "cr" THEN {"dr"} ELSE {"d4"}]
D_Empty == [c \in D_Commits |-> {}]
D_None == [c \in D_Commits |-> 99]
D_Zero == [c \in D_Commits |-> 0]
D_Exp == F(D_Commits, "c4", 1, 99)

(* K: a write kept until T = 1, a snapshot covering it; a writer and a       *)
(* reader; compaction only past T.                                           *)
K_Commits == {"c5", "s"}
K_Author == [c \in K_Commits |-> "w1"]
K_Deps == [c \in K_Commits |-> IF c = "s" THEN {"c5"} ELSE {}]
K_CD == [c \in K_Commits |-> IF c = "s" THEN {"ds"} ELSE {"d5"}]
K_Empty == [c \in K_Commits |-> {}]
K_Covers == F(K_Commits, "s", {"d5"}, {})
K_None == [c \in K_Commits |-> 99]
K_Until == F(K_Commits, "c5", 1, 0)
K_Zero == [c \in K_Commits |-> 0]

(* A: a write kept D = 1 after replaced: c7 kills d5; the writer compacts   *)
(* only past the kill plus D; a reader drops nothing but as covered.         *)
A_Commits == {"c5", "c7", "s"}
A_Author == [c \in A_Commits |-> "w1"]
A_Deps == [c \in A_Commits |-> CASE c = "c5" -> {} [] c = "c7" -> {"c5"} [] c = "s" -> {"c7"}]
A_CD == [c \in A_Commits |-> CASE c = "c5" -> {"d5"} [] c = "c7" -> {"d7"} [] c = "s" -> {"ds"}]
A_Empty == [c \in A_Commits |-> {}]
A_Kills == F(A_Commits, "c7", {"d5"}, {})
A_Covers == F(A_Commits, "s", {"d5", "d7"}, {})
A_None == [c \in A_Commits |-> 99]
A_Zero == [c \in A_Commits |-> 0]
A_After == F(A_Commits, "c5", 1, 0)
=============================================================================
