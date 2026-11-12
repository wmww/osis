------------------------------- MODULE Merge -------------------------------
(* Merging forks of one role of one actor (spec/crypto.md §4, Merger).      *)
(* Forks made at once by several rotators reach the nodes in any order and   *)
(* any subsets; a node merges whenever the rule names it the merger and it   *)
(* holds more than one current epoch (a merge lists every current epoch it   *)
(* holds, so supersedes them). Rule "roster": the merger is one node read   *)
(* from rosters (Leader), whatever epochs a node holds. Rule "maker": the    *)
(* maker of the newest current epoch other than the newest, as each node     *)
(* sees it (a rule over the forks held). Departures and due rotations are    *)
(* outside: every fork covers what it must, so only merges are made.         *)
EXTENDS Naturals, FiniteSets, Sequences

CONSTANTS Nodes,     \* the nodes that may rotate the role
          Forkers,   \* a sequence of nodes, each making one fork at once
          Leader,    \* the merger, under Rule "roster"
          Rule,      \* "roster" or "maker"
          MaxE       \* bound on epochs (a state bound for the "maker" rule)

VARIABLES ep,   \* epochs: [n, lists, by, merge]; 1 is the epoch forked from
          held  \* held[x]: the epochs node x holds

vars == <<ep, held>>
K == Len(Forkers)
Ids == 1..Len(ep)

RECURSIVE Anc(_)
Anc(e) == ep[e].lists \cup UNION {Anc(f) : f \in ep[e].lists}

Cur(x) == held[x] \ UNION {ep[e].lists : e \in held[x]}
\* (n, then id as the nonce): newer
Newer(a, b) == ep[a].n > ep[b].n \/ (ep[a].n = ep[b].n /\ a > b)
NewestOf(s) == CHOOSE e \in s : \A f \in s : f = e \/ Newer(e, f)

Merger(x) ==
  IF Rule = "roster" THEN x = Leader
  ELSE LET others == Cur(x) \ {NewestOf(Cur(x))}
       IN others # {} /\ ep[NewestOf(others)].by = x

Init ==
  /\ ep = <<[n |-> 0, lists |-> {}, by |-> "", merge |-> FALSE]>> \o
          [i \in 1..K |-> [n |-> 1, lists |-> {1}, by |-> Forkers[i], merge |-> FALSE]]
  /\ held = [x \in Nodes |-> {1} \cup {i + 1 : i \in {j \in 1..K : Forkers[j] = x}}]

Deliver(x, e) ==
  /\ e \notin held[x] /\ \E y \in Nodes : e \in held[y]
  /\ held' = [held EXCEPT ![x] = @ \cup {e}]
  /\ UNCHANGED ep

Merge(x) ==
  /\ Merger(x) /\ Cardinality(Cur(x)) > 1 /\ Len(ep) < MaxE
  /\ LET c == Cur(x)
     IN ep' = Append(ep, [n |-> 1 + ep[NewestOf(c)].n, lists |-> c, by |-> x, merge |-> TRUE])
  /\ held' = [held EXCEPT ![x] = @ \cup {Len(ep) + 1}]

Next == \E x \in Nodes : Merge(x) \/ \E e \in Ids : Deliver(x, e)

Spec == Init /\ [][Next]_vars /\ \A x \in Nodes : WF_vars(Merge(x)) /\ WF_vars(\E e \in Ids : Deliver(x, e))

Merges == {e \in Ids : ep[e].merge}
\* merges never fork each other: each lists (through others) every earlier one
MergesChain == \A a, b \in Merges : a = b \/ a \in Anc(b) \/ b \in Anc(a)
\* a fork of K epochs settles in at most K - 1 merges
MergeBound == Cardinality(Merges) <= K - 1
\* every node ends holding one current epoch, the same one
Settles == <>[](\E e \in Ids : \A x \in Nodes : Cur(x) = {e})
=============================================================================
