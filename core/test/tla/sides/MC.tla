---------------------------------- MODULE MC ----------------------------------
(* Scenarios for Sides; each .cfg picks one prefix and a mode. Nodes: the     *)
(* parties x (side X) and y (side Y) and a member m that may switch.          *)
EXTENDS Sides

R(w, pol, kind, purge) == [w |-> w, pol |-> pol, kind |-> kind, purge |-> purge]
Not(w) == R(w, "valid", "not", FALSE)
NoR(B) == [b \in B |-> {}]
Both(B) == [b \in B |-> Sides]
In(B, a) == [b \in B |-> a]

\* K: Y's write k supersedes m's pre-dispute b0 (keep at most 0 after
\* replaced). Side Y deletes b0; side X keeps it live. m starts on Y.
K_Bodies == {"b0", "k"}
K_Valid == [b \in K_Bodies |-> IF b = "k" THEN {"Y"} ELSE Sides]
K_Seed == [b \in K_Bodies |-> b = "k"]
K_Reasons == [b \in K_Bodies |-> IF b = "b0" THEN {Not("k")} ELSE {}]
K_Held == [n \in {"x", "y", "m"} |-> CASE n = "y" -> {"k"} [] n = "m" -> {"b0"} [] OTHER -> {}]
K_SideY == [n \in {"x", "y", "m"} |-> IF n = "x" THEN "X" ELSE "Y"]
K_SideX == [n \in {"x", "y", "m"} |-> IF n = "y" THEN "Y" ELSE "X"]

\* Z: z by a device X granted after the dispute (valid on X only, no direct
\* seed) supersedes b0. m starts on X.
Z_Bodies == {"b0", "z"}
Z_Valid == [b \in Z_Bodies |-> IF b = "z" THEN {"X"} ELSE Sides]
Z_Seed == [b \in Z_Bodies |-> FALSE]
Z_Reasons == [b \in Z_Bodies |-> IF b = "b0" THEN {Not("z")} ELSE {}]
Z_Held == [n \in {"x", "y", "m"} |-> CASE n = "x" -> {"z"} [] n = "m" -> {"b0"} [] OTHER -> {}]

\* F: X's post-dispute write w under keep at most 0 falls on side Y (an
\* invalid write counts dead from its fall); u is an outside body. m on Y.
F_Bodies == {"w", "u"}
F_Valid == [b \in F_Bodies |-> IF b = "w" THEN {"X"} ELSE Sides]
F_Seed == [b \in F_Bodies |-> b = "w"]
F_Reasons == [b \in F_Bodies |-> IF b = "w" THEN {R("w", "invalid", "not", FALSE)} ELSE {}]
F_Held == [n \in {"x", "y", "m"} |-> CASE n = "x" -> {"w"} [] n = "m" -> {"u"} [] OTHER -> {}]

\* C: X's post-dispute snapshot s covers b0 (one-side cover). m on X holds
\* b0, which is at the host; y has not fetched it yet.
C_Bodies == {"b0", "s"}
C_Valid == [b \in C_Bodies |-> IF b = "s" THEN {"X"} ELSE Sides]
C_Seed == [b \in C_Bodies |-> b = "s"]
C_Reasons == [b \in C_Bodies |-> IF b = "b0" THEN {R("s", "valid", "cover", FALSE)} ELSE {}]
C_Held == [n \in {"x", "y", "m"} |-> CASE n = "x" -> {"s"} [] n = "m" -> {"b0"} [] OTHER -> {}]

\* P: a purge p both sides accept names b1; Y's post-dispute write d is on
\* b1's aspect. m on Y holds b1 and p.
P_Bodies == {"b1", "p", "d"}
P_Valid == [b \in P_Bodies |-> IF b = "d" THEN {"Y"} ELSE Sides]
P_Seed == [b \in P_Bodies |-> b = "d"]
P_Reasons == [b \in P_Bodies |-> IF b = "b1" THEN {R("p", "valid", "not", TRUE)} ELSE {}]
P_Held == [n \in {"x", "y", "m"} |-> CASE n = "y" -> {"d"} [] n = "m" -> {"b1", "p"} [] OTHER -> {}]
P_Aspect == [b \in P_Bodies |-> IF b = "p" THEN "pa" ELSE "a"]

\* Q: Y's placement q keeps t in the label's required set; on side X, t is
\* outside it (must-not-hold while q is invalid or not held). m on Y
\* holds both.
Q_Bodies == {"t", "q"}
Q_Valid == [b \in Q_Bodies |-> IF b = "q" THEN {"Y"} ELSE Sides]
Q_Seed == [b \in Q_Bodies |-> b = "q"]
Q_Reasons == [b \in Q_Bodies |-> IF b = "t" THEN {R("q", "invalid", "not", FALSE)} ELSE {}]
Q_Held == [n \in {"x", "y", "m"} |-> CASE n = "y" -> {"q"} [] n = "m" -> {"t", "q"} [] OTHER -> {}]
OneAspect == [b \in UNION {K_Bodies, Z_Bodies, F_Bodies, C_Bodies, P_Bodies, Q_Bodies} |-> "a"]
=============================================================================
