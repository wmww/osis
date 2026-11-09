------------------------------- MODULE Authority -------------------------------
(* Whether rotation validity is one function of the held set once a rotation  *)
(* failing Authority is invalid as a whole, keyset included (spec/crypto.md   *)
(* §4 Holder actors, Possession, Authority).                                *)
(* Authority of a rotation of actor a by an author whose role runs only       *)
(* through holder actor h reads h's held valid keysets: h counts while one is *)
(* held, and the proof for h its keyset carries shows it when it is signed   *)
(* by the possession key of the keyset of h it names, or when that keyset has *)
(* no valid body held (not judged). A rotation's keyset is valid iff it is   *)
(* is, so validity feeds Authority and Authority validity, around holder-     *)
(* actor cycles. The adversary picks every rotation (its actor, the keyset it *)
(* names, whether its signature verifies, the key order); a node receives     *)
(* them in any order and re-judges one at a time until nothing changes, as   *)
(* the engine does. Rule "held": Authority reads the keysets held now. Rule   *)
(* "order": it reads them as of just before the rotation's key (a body        *)
(* ordered at or after it counts as not held), as it reads the author's roles.*)
EXTENDS Naturals, FiniteSets

CONSTANTS Acts,     \* actors
          Hold,     \* {<<h, a>>}: holder actor h holds a role on actor a
          NR,       \* rotations, each by an author reaching its actor only
                    \* through one holder actor
          Base,     \* actors with a keyset valid by role alone (a rotation by
                    \* a direct admin), ordered before every rotation
          Rule      \* "held" or "order"

R == 1..NR
Via(a) == {q[1] : q \in {p \in Hold : p[2] = a}}
Rots == {a \in Acts : Via(a) # {}}

VARIABLES cf,   \* the rotations: [r |-> [act, via, names (0: none), sig, key]]
          held, \* rotations the node holds
          val   \* the node's verdicts on them

vars == <<cf, held, val>>

Cfgs == {c \in [R -> [act : Rots, via : Acts, names : 0..NR, sig : BOOLEAN, key : R]] :
           /\ \A r \in R : c[r].via \in Via(c[r].act)
           /\ \A r \in R : c[r].names # 0 => (c[r].names # r /\ c[c[r].names].act = c[r].via)
           /\ \A r, q \in R : r # q => c[r].key # c[q].key}

\* rotation q counts for rotation r under verdicts v: held, valid, and (rule
\* "order") ordered before r
Counts(v, H, q, r) == q \in H /\ v[q] /\ (Rule = "held" \/ cf[q].key < cf[r].key)
\* Authority of r under verdicts v over held set H
Judge(v, H, r) ==
  LET h == cf[r].via
      k == cf[r].names
      hasKs == h \in Base \/ \E q \in R : cf[q].act = h /\ Counts(v, H, q, r)
      shown == k # 0 /\ (cf[r].sig \/ ~Counts(v, H, k, r))
  IN ~hasKs \/ shown

Init == /\ cf \in Cfgs
        /\ held = {}
        /\ val = [r \in R |-> FALSE]

Arrive == \E r \in R \ held :
            /\ held' = held \cup {r}
            /\ val' = [val EXCEPT ![r] = Judge(val, held', r)]
            /\ UNCHANGED cf
Rejudge == \E r \in held :
             /\ val[r] # Judge(val, held, r)
             /\ val' = [val EXCEPT ![r] = ~@]
             /\ UNCHANGED <<cf, held>>

Next == Arrive \/ Rejudge
Spec == Init /\ [][Next]_vars /\ WF_vars(Next)

Done == held = R /\ \A r \in R : val[r] = Judge(val, R, r)

Fixpoint(w) == \A r \in R : w[r] = Judge(w, R, r)
\* every complete, settled node holds the same verdicts: the one fixpoint
OneResult == Done => \A w \in [R -> BOOLEAN] : Fixpoint(w) => w = val
\* and re-judging ends
Ends == <>Done
=============================================================================
