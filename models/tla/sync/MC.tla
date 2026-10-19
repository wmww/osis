--------------------------------- MODULE MC ---------------------------------
(* Scenarios for SyncConvergence; each .cfg picks one prefix.                *)
EXTENDS SyncConvergence

F(dom, c0, v0, dflt) == [c \in dom |-> IF c = c0 THEN v0 ELSE dflt]

(* T: supersede under a relative keep-at-most (timed delete), compaction     *)
(* snapshot, two writers.                                                    *)
T_Commits == {"c1", "c2", "s"}
T_Author == [c \in T_Commits |-> IF c = "c2" THEN "w2" ELSE "w1"]
T_Deps == [c \in T_Commits |-> CASE c = "c1" -> {} [] c = "c2" -> {"c1"} [] c = "s" -> {"c2"}]
T_CD == [c \in T_Commits |-> CASE c = "c1" -> {"d1"} [] c = "c2" -> {"d2"} [] c = "s" -> {"ds"}]
T_Kills == F(T_Commits, "c2", {"d1"}, {})
T_Covers == F(T_Commits, "s", {"d1", "d2"}, {})
T_Purges == [c \in T_Commits |-> {}]
T_None == [c \in T_Commits |-> 99]
T_MostRel == F(T_Commits, "c1", 1, 99)

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

(* D: a non-writer deposits a commit a writer promotes; an expiring write;  *)
(* a reader relays; the server replays a stale entry.                        *)
D_Commits == {"cr", "c4"}
D_Author == [c \in D_Commits |-> IF c = "cr" THEN "r" ELSE "w1"]
D_Deps == [c \in D_Commits |-> {}]
D_CD == [c \in D_Commits |-> IF c = "cr" THEN {"dr"} ELSE {"d4"}]
D_Empty == [c \in D_Commits |-> {}]
D_None == [c \in D_Commits |-> 99]
D_Exp == F(D_Commits, "c4", 1, 99)

(* M: a live write under an absolute keep-at-most, its snapshot carrying the *)
(* aspect's bounds (commits §5), a writer and a reader.                      *)
M_Commits == {"c5", "s"}
M_Author == [c \in M_Commits |-> "w1"]
M_Deps == [c \in M_Commits |-> IF c = "s" THEN {"c5"} ELSE {}]
M_CD == [c \in M_Commits |-> IF c = "s" THEN {"ds"} ELSE {"d5"}]
M_Empty == [c \in M_Commits |-> {}]
M_Covers == F(M_Commits, "s", {"d5"}, {})
M_None == [c \in M_Commits |-> 99]
M_MostAbs == [c \in M_Commits |-> 1]
=============================================================================
