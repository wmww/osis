---- MODULE NetTrust ----
(* How an account P holding sync alone on thing T learns T's sync IDs and sync secrets
   (spec/sync.md §3 The account's sync record). Principle: a node keeping T unread trusts only its
   own account: T's sync IDs come only from the account's own judgement (the user's accept of an
   offer, or its reading of T's `sync.0` before it was lowered), and a sync secret only once a step
   on its own path of such a sync ID bears its sync key. What a node of P so learns it writes into
   the account's record (`kept^.0` on D), which every node of P reads, now or joining later.

   Parties: the genuine admin A (rotates, may remove P and re-grant it, registers S's steps at a
   node of P that shows a key it holds, boxes P each epoch P holds; its box stays in P's inbox until
   a node of P recorded its secret, then may expire); a forger F knowing T and P's inbox key (sends
   offers of its own sync ID SF with its own key FK; with Insider, a connected non-admin knowing S,
   it may name S); a removed admin R (removed at epoch 1, it holds step 0's delete key: it may
   register a child of step 0 bearing its own key RK at a node of P whose head is step 0, and box
   P RK). Nodes n1 (from the start) and n2 (with Late, joining at any time, typically after every
   box expired). P's inbox is shared by its nodes. The user accepts any offer naming a sync ID the
   record lacks (it cannot tell F's offer from A's), adding every held offer's sync ID.

   Rules as flags; controls: Vouch (an offer's sync ID is taken without an accept: the connected
   rule), AnySecret (a box's secret is recorded without a step bearing it), LocalOnly (each node
   keeps its own record: nothing in D). *)
EXTENDS Integers, FiniteSets

CONSTANTS
    MaxEp,      \* genuine sync epochs after the first
    Regrant,    \* A may re-grant P once after removing it
    Forge,      \* a forger sends offers
    Insider,    \* ... knowing S (a connected non-admin)
    Removed,    \* a removed admin forks step 0
    Late,       \* n2 joins at any time
    Lowered,    \* P starts lowered from read: its record holds S and epoch 0 by its own reading
    Vouch,      \* control: an offer's sync ID is taken without an accept
    AnySecret,  \* control: a box's secret is recorded unconfirmed
    LocalOnly   \* control: no shared record

Nodes == {"n1", "n2"}
Ids == {"S", "SF"}
FK == MaxEp + 1
RK == MaxEp + 2
None == -1
RStep == MaxEp + 10   \* R's fork child of step 0

VARIABLES
    epoch, removedAt, regrantAt,   \* A's state (removedAt, regrantAt: an epoch, or -1)
    inbox,      \* offers held in P's inbox: [sid, key]
    rec,        \* rec[n]: the record node n reads: [ids, secs]
    accepted,   \* ghost: the sync IDs an accept took
    joined,     \* the nodes of P so far
    head,       \* head[n][sid]: a step ID (genuine: 0..MaxEp; R's fork: RStep), or None
    path,       \* path[n][sid]: the steps registered at n
    fsent, rsent
vars == <<epoch, removedAt, regrantAt, inbox, rec, accepted, joined, head, path, fsent, rsent>>

KeyOf(sid, st) == IF sid = "SF" THEN FK ELSE IF st = RStep THEN RK ELSE st
PathKeys(n, sid) == {KeyOf(sid, st) : st \in path[n][sid]}
Cands == {b.key : b \in inbox}
\* what node n holds as credentials of T: its record's secrets and the boxes of offers it holds
Held(n) == rec[n].secs \cup Cands
\* the nodes whose record a write by n reaches (D: all of P's, joined or not)
Writers(n) == IF LocalOnly THEN {n} ELSE Nodes
Write(n, f(_)) == [m \in Nodes |-> IF m \in Writers(n) THEN f(rec[m]) ELSE rec[m]]

Init ==
    /\ epoch = 0 /\ removedAt = -1 /\ regrantAt = -1
    /\ inbox = IF Lowered THEN {} ELSE {[sid |-> "S", key |-> 0]}
    /\ rec = [n \in Nodes |-> IF Lowered THEN [ids |-> {"S"}, secs |-> {0}] ELSE [ids |-> {}, secs |-> {}]]
    /\ accepted = {}
    /\ joined = IF Late THEN {"n1"} ELSE Nodes
    /\ head = [n \in Nodes |-> [s \in Ids |-> None]]
    /\ path = [n \in Nodes |-> [s \in Ids |-> {}]]
    /\ fsent = 0 /\ rsent = FALSE

\* the epochs A boxed P at
Boxed == {e \in 0..epoch : (removedAt < 0 \/ e < removedAt) \/ (regrantAt >= 0 /\ e >= regrantAt)}

Rotate(remove) ==
    /\ epoch < MaxEp
    /\ remove => removedAt < 0
    /\ epoch' = epoch + 1
    /\ removedAt' = IF remove THEN epoch + 1 ELSE removedAt
    /\ inbox' = IF ~remove /\ (removedAt < 0 \/ regrantAt >= 0) THEN inbox \cup {[sid |-> "S", key |-> epoch + 1]} ELSE inbox
    /\ UNCHANGED <<regrantAt, rec, accepted, joined, head, path, fsent, rsent>>

Regive ==
    /\ Regrant /\ removedAt >= 0 /\ regrantAt < 0 /\ epoch >= removedAt
    /\ regrantAt' = epoch
    /\ inbox' = inbox \cup {[sid |-> "S", key |-> epoch]}
    /\ UNCHANGED <<epoch, removedAt, rec, accepted, joined, head, path, fsent, rsent>>

\* F offers its own sync ID (or, an insider, S) with its own key
ForgeSend(sid) ==
    /\ Forge /\ fsent < 2 /\ (sid = "S" => Insider)
    /\ fsent' = fsent + 1
    /\ inbox' = inbox \cup {[sid |-> sid, key |-> FK]}
    /\ UNCHANGED <<epoch, removedAt, regrantAt, rec, accepted, joined, head, path, rsent>>

\* the user accepts an offer naming a sync ID its record lacks: every held offer's sync ID taken
Accept(n) ==
    /\ n \in joined
    /\ \E b \in inbox : b.sid \notin rec[n].ids
    /\ rec' = Write(n, LAMBDA r : [r EXCEPT !.ids = @ \cup {b.sid : b \in inbox}])
    /\ accepted' = accepted \cup {b.sid : b \in inbox}
    /\ UNCHANGED <<epoch, removedAt, regrantAt, inbox, joined, head, path, fsent, rsent>>

\* control: an offer's sync ID taken on the sender's word (the connected rule)
AutoTake(n) ==
    /\ Vouch /\ n \in joined
    /\ \E b \in inbox : b.sid \notin rec[n].ids
    /\ rec' = Write(n, LAMBDA r : [r EXCEPT !.ids = @ \cup {b.sid : b \in inbox}])
    /\ UNCHANGED <<epoch, removedAt, regrantAt, inbox, accepted, joined, head, path, fsent, rsent>>

\* what n shows for S: its head's key when held, else the held keys no step of its path bears
Shown(n) ==
    IF head[n]["S"] # None /\ KeyOf("S", head[n]["S"]) \in Held(n) THEN {KeyOf("S", head[n]["S"])}
    ELSE Held(n) \ PathKeys(n, "S")
Opens(n) == Shown(n) \cap (0..epoch) # {}

MoveHead(n, sid, st) ==
    /\ head' = [head EXCEPT ![n][sid] = st]
    /\ path' = [path EXCEPT ![n][sid] = @ \cup {st}]

\* A registers S's next step at n, S open there (genesis first with no head)
AdminRegister(n) ==
    /\ n \in joined /\ "S" \in rec[n].ids /\ Opens(n)
    /\ LET h == head[n]["S"] IN
         \/ (h = None /\ MoveHead(n, "S", 0))
         \/ (h # None /\ h # RStep /\ h < epoch /\ MoveHead(n, "S", h + 1))
    /\ UNCHANGED <<epoch, removedAt, regrantAt, inbox, rec, accepted, joined, fsent, rsent>>

\* R registers its fork child of step 0 at n (no open needed) and boxes P its key
RFork(n) ==
    /\ Removed /\ ~rsent /\ n \in joined /\ epoch >= 1 /\ head[n]["S"] = 0
    /\ rsent' = TRUE
    /\ MoveHead(n, "S", RStep)
    /\ inbox' = inbox \cup {[sid |-> "S", key |-> RK]}
    /\ UNCHANGED <<epoch, removedAt, regrantAt, rec, accepted, joined, fsent>>

\* F registers SF's genesis at n, which keeps SF
FRegister(n) ==
    /\ Forge /\ n \in joined /\ "SF" \in rec[n].ids /\ head[n]["SF"] = None
    /\ MoveHead(n, "SF", 0)
    /\ UNCHANGED <<epoch, removedAt, regrantAt, inbox, rec, accepted, joined, fsent, rsent>>

\* n records a held box's secret once a step on its path of a recorded sync ID bears its key
Confirm(n, x) ==
    /\ n \in joined /\ x \in Cands /\ x \notin rec[n].secs
    /\ IF AnySecret THEN rec[n].ids # {} ELSE \E s \in rec[n].ids : x \in PathKeys(n, s)
    /\ rec' = Write(n, LAMBDA r : [r EXCEPT !.secs = @ \cup {x}])
    /\ UNCHANGED <<epoch, removedAt, regrantAt, inbox, accepted, joined, head, path, fsent, rsent>>

\* an offer expires: A's once P recorded its secret (it saw P take it), any other at any time
Expire(b) ==
    /\ b \in inbox
    /\ (b.sid = "S" /\ b.key \in 0..MaxEp) => \E n \in joined : b.key \in rec[n].secs
    /\ inbox' = inbox \ {b}
    /\ UNCHANGED <<epoch, removedAt, regrantAt, rec, accepted, joined, head, path, fsent, rsent>>

Join ==
    /\ "n2" \notin joined
    /\ joined' = Nodes
    /\ UNCHANGED <<epoch, removedAt, regrantAt, inbox, rec, accepted, head, path, fsent, rsent>>

AcceptGenuine == \E n \in joined : "S" \notin rec[n].ids /\ \E b \in inbox : b.sid = "S" /\ b.key \in 0..MaxEp

Next == \/ Rotate(TRUE) \/ Rotate(FALSE) \/ Regive \/ Join
        \/ \E s \in Ids : ForgeSend(s)
        \/ \E n \in Nodes : Accept(n) \/ AutoTake(n) \/ AdminRegister(n) \/ RFork(n) \/ FRegister(n)
        \/ \E n \in Nodes, x \in 0..RK : Confirm(n, x)
        \/ \E b \in inbox : Expire(b)
Spec == Init /\ [][Next]_vars

\* No attach: every sync ID a record holds an accept took, or the account's own reading gave.
NoAttach == \A n \in Nodes : rec[n].ids \subseteq accepted \cup (IF Lowered THEN {"S"} ELSE {})
\* No plant: every secret a record holds is a genuine epoch's, the accepted forger's own on its
\* own sync ID, or the removed admin's on its fork (the stated limit).
NoPlant == \A n \in Nodes : rec[n].secs \subseteq
    (0..epoch) \cup (IF "SF" \in rec[n].ids THEN {FK} ELSE {}) \cup (IF rsent THEN {RK} ELSE {})
\* Removed: no record holds a genuine secret of an epoch A did not box P at.
RemovedNothing == \A n \in Nodes : rec[n].secs \cap (0..epoch) \subseteq Boxed
\* captured by R's fork: the stated limit (spec/sync-hostile.md §2)
Captured(n) == RStep \in path[n]["S"]
\* quiet: every genuine step done, every node joined (Late)
Quiet == epoch = MaxEp /\ joined = Nodes /\ ~AcceptGenuine
         /\ \A n \in Nodes : ~ENABLED AdminRegister(n) /\ \A x \in 0..RK : ~ENABLED Confirm(n, x)
\* Live: quiet, P boxed at the current epoch: every node not captured is at A's head holding its key
Live == (Quiet /\ epoch \in Boxed) =>
    \A n \in Nodes : ~Captured(n) => (head[n]["S"] = epoch /\ epoch \in rec[n].secs)
====
