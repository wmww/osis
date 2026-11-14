---- MODULE NetTrust ----
(* How an account P holding sync alone on thing T learns T's sync IDs and sync secrets
   (spec/sync.md §3 The account's sync record). Principle: a node keeping T unread trusts only its
   own account: T's sync IDs come only from the account's own judgement (the user's accept of an
   offer, or its reading of T's `sync.0` before it was lowered), a sync secret only once a step on
   its own path of such a sync ID bears its sync key, and a sync ID kept for several things is
   synced for those a step on its path ties it to (a step bearing the sync key of a held secret of
   the thing), whatever order the accepts came in. What a node of P so learns it writes into the
   account's record (`kept^.0` on D), which every node of P reads, now or joining later.

   Parties: the genuine admin A of T (rotates, may remove P and re-grant it, registers S's steps at
   a node of P that shows a key it holds, boxes P each epoch P holds; its box stays in P's inbox
   until a node of P recorded its secret, then may expire); a forger F knowing T and P's inbox key
   (sends offers of T under its own sync ID SF with its own key FK; with Insider, a connected
   non-admin knowing S, it may name S for T; with Other, also for its own thing U; with Relabel, a
   holder of T's sync secret, it may box T's genesis sync secret as U's under S); a removed admin R
   (removed at epoch 1, it holds step 0's delete key: it may register a child of step 0 bearing
   its own key RK at a node of P whose head is step 0, and box P RK for T). Nodes n1 (from the
   start) and n2 (with Late, joining at any time, typically after every box expired). P's inbox is
   shared by its nodes. The user accepts any held offer of any thing, in any order (it cannot tell
   F's offers from A's): the accept keeps every held offer's sync ID for that thing.

   Rules as flags; controls: Vouch (an offer's sync ID is taken without an accept: the connected
   rule), AnySecret (a box's secret is recorded without a step bearing it), LocalOnly (each node
   keeps its own record: nothing in D), FirstCome (an accept keeps no sync ID the record keeps for
   another thing), NoTie (a sync ID is synced for every thing keeping it, tied or not). *)
EXTENDS Integers, FiniteSets

CONSTANTS
    MaxEp,      \* genuine sync epochs after the first
    Regrant,    \* A may re-grant P once after removing it
    Forge,      \* a forger sends offers
    Insider,    \* ... knowing S (a connected non-admin)
    Other,      \* ... offers its own thing U under S
    Relabel,    \* ... holding T's sync secret: boxes it as U's
    Removed,    \* a removed admin forks step 0
    Late,       \* n2 joins at any time
    Lowered,    \* P starts lowered from read: its record holds S and epoch 0 by its own reading
    Vouch,      \* control: an offer's sync ID is taken without an accept
    AnySecret,  \* control: a box's secret is recorded unconfirmed
    LocalOnly,  \* control: no shared record
    FirstCome,  \* control: an accept keeps no sync ID kept for another thing
    NoTie       \* control: a sync ID is synced for every thing keeping it

Nodes == {"n1", "n2"}
Things == {"T", "U"}
Ids == {"S", "SF"}
FK == MaxEp + 1
RK == MaxEp + 2
None == -1
RStep == MaxEp + 10   \* R's fork child of step 0

VARIABLES
    epoch, removedAt, regrantAt,   \* A's state (removedAt, regrantAt: an epoch, or -1)
    inbox,      \* offers held in P's inbox: [th, sid, key]
    rec,        \* rec[n]: the record node n reads: per thing [ids, secs, tied], and `seen`
    accepted,   \* ghost: accepted[th]: the sync IDs an accept took for th
    joined,     \* the nodes of P so far
    head,       \* head[n][sid]: a step ID (genuine: 0..MaxEp; R's fork: RStep), or None
    path,       \* path[n][sid]: the steps registered at n
    fsent, rsent
vars == <<epoch, removedAt, regrantAt, inbox, rec, accepted, joined, head, path, fsent, rsent>>

Empty == [ids |-> {}, secs |-> {}, tied |-> {}]
KeyOf(sid, st) == IF sid = "SF" THEN FK ELSE IF st = RStep THEN RK ELSE st
PathKeys(n, sid) == {KeyOf(sid, st) : st \in path[n][sid]}
Cands(th) == {b.key : b \in {o \in inbox : o.th = th}}
\* what node n holds as credentials of thing th: its record's secrets and the boxes of offers held
HeldOf(n, th) == rec[n].r[th].secs \cup Cands(th)
\* the things whose record keeps sid, those tied to it, and those it is synced for
Keeps(n, sid) == {th \in Things : sid \in rec[n].r[th].ids}
Tied(n, sid) == {th \in Things : sid \in rec[n].r[th].tied}
ThingsOf(n, sid) == IF Tied(n, sid) # {} /\ ~NoTie THEN Tied(n, sid) ELSE Keeps(n, sid)
Held(n, sid) == UNION {HeldOf(n, th) : th \in ThingsOf(n, sid)}
\* the nodes whose record a write by n reaches (D: all of P's, joined or not)
Writers(n) == IF LocalOnly THEN {n} ELSE Nodes
Write(n, f(_)) == [m \in Nodes |-> IF m \in Writers(n) THEN f(rec[m]) ELSE rec[m]]
SetR(r, th, g(_)) == [r EXCEPT !.r[th] = g(@)]

Init ==
    /\ epoch = 0 /\ removedAt = -1 /\ regrantAt = -1
    /\ inbox = IF Lowered THEN {} ELSE {[th |-> "T", sid |-> "S", key |-> 0]}
    /\ rec = [n \in Nodes |-> [seen |-> {},
              r |-> [th \in Things |-> IF Lowered /\ th = "T" THEN [ids |-> {"S"}, secs |-> {0}, tied |-> {"S"}] ELSE Empty]]]
    /\ accepted = [th \in Things |-> {}]
    /\ joined = IF Late THEN {"n1"} ELSE Nodes
    /\ head = [n \in Nodes |-> [s \in Ids |-> None]]
    /\ path = [n \in Nodes |-> [s \in Ids |-> {}]]
    /\ fsent = 0 /\ rsent = FALSE

\* the epochs A boxed P at
Boxed == {e \in 0..epoch : (removedAt < 0 \/ e < removedAt) \/ (regrantAt >= 0 /\ e >= regrantAt)}
Genuine(e) == [th |-> "T", sid |-> "S", key |-> e]

Rotate(remove) ==
    /\ epoch < MaxEp
    /\ remove => removedAt < 0
    /\ epoch' = epoch + 1
    /\ removedAt' = IF remove THEN epoch + 1 ELSE removedAt
    /\ inbox' = IF ~remove /\ (removedAt < 0 \/ regrantAt >= 0) THEN inbox \cup {Genuine(epoch + 1)} ELSE inbox
    /\ UNCHANGED <<regrantAt, rec, accepted, joined, head, path, fsent, rsent>>

Regive ==
    /\ Regrant /\ removedAt >= 0 /\ regrantAt < 0 /\ epoch >= removedAt
    /\ regrantAt' = epoch
    /\ inbox' = inbox \cup {Genuine(epoch)}
    /\ UNCHANGED <<epoch, removedAt, rec, accepted, joined, head, path, fsent, rsent>>

\* what F may offer: T under its own SF with FK; an insider names S for T, or (Other) for its own
\* thing U; a holder of T's sync secret boxes it as U's under S
Forgeable ==
    {[th |-> "T", sid |-> "SF", key |-> FK]}
    \cup (IF Insider THEN {[th |-> "T", sid |-> "S", key |-> FK]} ELSE {})
    \cup (IF Other THEN {[th |-> "U", sid |-> "S", key |-> FK]} ELSE {})
    \cup (IF Other /\ Relabel THEN {[th |-> "U", sid |-> "S", key |-> 0]} ELSE {})

ForgeSend(b) ==
    /\ Forge /\ fsent < 2 /\ b \notin inbox
    /\ fsent' = fsent + 1
    /\ inbox' = inbox \cup {b}
    /\ UNCHANGED <<epoch, removedAt, regrantAt, rec, accepted, joined, head, path, rsent>>

\* the user accepts the held offers of th it has not acted on: every one's sync ID kept for th
Accept(n, th) ==
    /\ n \in joined
    /\ \E b \in inbox : b.th = th /\ b \notin rec[n].seen
    /\ LET offered == {b \in inbox : b.th = th}
           ids == {b.sid : b \in offered} \ (IF FirstCome THEN UNION {rec[n].r[x].ids : x \in Things \ {th}} ELSE {})
       IN /\ rec' = Write(n, LAMBDA r : [SetR(r, th, LAMBDA x : [x EXCEPT !.ids = @ \cup ids]) EXCEPT !.seen = @ \cup offered])
          /\ accepted' = [accepted EXCEPT ![th] = @ \cup ids]
    /\ UNCHANGED <<epoch, removedAt, regrantAt, inbox, joined, head, path, fsent, rsent>>

\* control: an offer's sync ID taken on the sender's word (the connected rule)
AutoTake(n, b) ==
    /\ Vouch /\ n \in joined /\ b \in inbox /\ b.sid \notin rec[n].r[b.th].ids
    /\ rec' = Write(n, LAMBDA r : SetR(r, b.th, LAMBDA x : [x EXCEPT !.ids = @ \cup {b.sid}]))
    /\ UNCHANGED <<epoch, removedAt, regrantAt, inbox, accepted, joined, head, path, fsent, rsent>>

\* what n shows for S: its head's key when held, else the held keys no step of its path bears
Shown(n) ==
    IF head[n]["S"] # None /\ KeyOf("S", head[n]["S"]) \in Held(n, "S") THEN {KeyOf("S", head[n]["S"])}
    ELSE Held(n, "S") \ PathKeys(n, "S")
Opens(n) == Shown(n) \cap (0..epoch) # {}

MoveHead(n, sid, st) ==
    /\ head' = [head EXCEPT ![n][sid] = st]
    /\ path' = [path EXCEPT ![n][sid] = @ \cup {st}]

\* A registers S's next step at n, S synced and open there (genesis first with no head)
AdminRegister(n) ==
    /\ n \in joined /\ ThingsOf(n, "S") # {} /\ Opens(n)
    /\ LET h == head[n]["S"] IN
         \/ (h = None /\ MoveHead(n, "S", 0))
         \/ (h # None /\ h # RStep /\ h < epoch /\ MoveHead(n, "S", h + 1))
    /\ UNCHANGED <<epoch, removedAt, regrantAt, inbox, rec, accepted, joined, fsent, rsent>>

\* R registers its fork child of step 0 at n (no open needed) and boxes P its key
RFork(n) ==
    /\ Removed /\ ~rsent /\ n \in joined /\ epoch >= 1 /\ head[n]["S"] = 0
    /\ rsent' = TRUE
    /\ MoveHead(n, "S", RStep)
    /\ inbox' = inbox \cup {[th |-> "T", sid |-> "S", key |-> RK]}
    /\ UNCHANGED <<epoch, removedAt, regrantAt, rec, accepted, joined, fsent>>

\* F registers SF's genesis at n, which syncs SF
FRegister(n) ==
    /\ Forge /\ n \in joined /\ ThingsOf(n, "SF") # {} /\ head[n]["SF"] = None
    /\ MoveHead(n, "SF", 0)
    /\ UNCHANGED <<epoch, removedAt, regrantAt, inbox, rec, accepted, joined, fsent, rsent>>

\* what a step on n's path of sid bears of th's held keys: sid tied to th, and each such held box's
\* secret recorded, in one write (`Engine::record_borne`); with AnySecret, any held box's secret
\* of a thing with a kept sync ID is recorded unconfirmed
Bears(n, th, sid) == HeldOf(n, th) \cap PathKeys(n, sid)
Borne(n, th, sid) ==
    /\ n \in joined /\ sid \in rec[n].r[th].ids /\ Bears(n, th, sid) # {}
    /\ LET new == IF AnySecret THEN Cands(th) ELSE Bears(n, th, sid) \cap Cands(th)
       IN /\ (sid \notin rec[n].r[th].tied \/ ~(new \subseteq rec[n].r[th].secs))
          /\ rec' = Write(n, LAMBDA r : SetR(r, th, LAMBDA x : [x EXCEPT !.tied = @ \cup {sid}, !.secs = @ \cup new]))
    /\ UNCHANGED <<epoch, removedAt, regrantAt, inbox, accepted, joined, head, path, fsent, rsent>>

\* an offer expires: A's once P recorded its secret (it saw P take it), any other at any time
Expire(b) ==
    /\ b \in inbox
    /\ (b.th = "T" /\ b.sid = "S" /\ b.key \in 0..MaxEp) => \E n \in joined : b.key \in rec[n].r["T"].secs
    /\ inbox' = inbox \ {b}
    /\ UNCHANGED <<epoch, removedAt, regrantAt, rec, accepted, joined, head, path, fsent, rsent>>

Join ==
    /\ "n2" \notin joined
    /\ joined' = Nodes
    /\ UNCHANGED <<epoch, removedAt, regrantAt, inbox, rec, accepted, head, path, fsent, rsent>>

\* the user has not yet acted on A's offer at some node
AcceptGenuine == \E n \in joined, b \in inbox : b.th = "T" /\ b.sid = "S" /\ b.key \in 0..MaxEp /\ b \notin rec[n].seen

Next == \/ Rotate(TRUE) \/ Rotate(FALSE) \/ Regive \/ Join
        \/ \E b \in Forgeable : ForgeSend(b)
        \/ \E n \in Nodes : AdminRegister(n) \/ RFork(n) \/ FRegister(n)
        \/ \E n \in Nodes, th \in Things : Accept(n, th)
        \/ \E n \in Nodes, b \in inbox : AutoTake(n, b)
        \/ \E n \in Nodes, th \in Things, s \in Ids : Borne(n, th, s)
        \/ \E b \in inbox : Expire(b)
Spec == Init /\ [][Next]_vars

\* No attach: every sync ID a record keeps for a thing an accept of that thing took, or the
\* account's own reading gave.
NoAttach == \A n \in Nodes, th \in Things :
    rec[n].r[th].ids \subseteq accepted[th] \cup (IF Lowered /\ th = "T" THEN {"S"} ELSE {})
\* No plant: every secret T's record holds is a genuine epoch's, the accepted forger's own on its
\* own sync ID, or the removed admin's on its fork (the stated limit); U's only its own, or T's
\* genesis secret a holder of it boxed as U's.
NoPlant == \A n \in Nodes :
    /\ rec[n].r["T"].secs \subseteq
        (0..epoch) \cup (IF "SF" \in rec[n].r["T"].ids THEN {FK} ELSE {}) \cup (IF rsent THEN {RK} ELSE {})
    /\ rec[n].r["U"].secs \subseteq {FK} \cup (IF Relabel THEN {0} ELSE {})
\* Owner: S is synced for U only while no step ties S to a thing, or once a step ties it to U
\* (only a holder of T's sync secret boxing it as U's can).
Owner == \A n \in Nodes :
    /\ "U" \in ThingsOf(n, "S") => (Tied(n, "S") = {} \/ "U" \in Tied(n, "S"))
    /\ "U" \in Tied(n, "S") => Relabel
\* Removed: no record holds a genuine secret of an epoch A did not box P at.
RemovedNothing == \A n \in Nodes : rec[n].r["T"].secs \cap (0..epoch) \subseteq Boxed
\* captured by R's fork: the stated limit (spec/sync-hostile.md §2)
Captured(n) == RStep \in path[n]["S"]
\* quiet: every genuine step done, every offer of A's acted on, every node joined (Late)
Quiet ==
    /\ epoch = MaxEp /\ joined = Nodes /\ ~AcceptGenuine
    /\ \A n \in Nodes : ~ENABLED AdminRegister(n)
    /\ \A n \in Nodes, th \in Things, s \in Ids : ~ENABLED Borne(n, th, s)
\* Live: quiet, P boxed at the current epoch: every node not captured is at A's head holding its
\* key, S tied to T, whatever was accepted first, and synced for U only if U is tied too
Live == (Quiet /\ epoch \in Boxed) =>
    \A n \in Nodes : ~Captured(n) =>
        /\ head[n]["S"] = epoch /\ epoch \in rec[n].r["T"].secs
        /\ "T" \in Tied(n, "S")
        /\ ThingsOf(n, "S") \subseteq Tied(n, "S")
====
