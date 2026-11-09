---- MODULE NetShared ----
(* The shared-set half of issues/net-shared-set.md: one sync ID between node
   "a" and its peer "b" (or "c", a copy of b's store). A credential is the
   sync ID's current epoch; the rule is a function of what each node holds.
   Beacons (whole and additions, generations, pending set), Hit and its tag,
   ByRole, Lost, a removal learned on one side, rotations carried through their
   event (`until`), record loss. A rule of the design is a flag. *)
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    Stores, MaxEp, MaxDrop, MaxRecLoss, MaxClone, MaxRot, MaxRemove, MaxGrant,
    RoleA, RoleB, EpA, EpB,         \* initial roles and epochs (0 = holds nothing of L)
    TestPending,                    \* issue: test the whole pending set, not only what is newly changed
    AckWaitsOffers,                 \* acked_pos waits for the Offers testing it caused
    TagCheck,                       \* a Hit's accept must show the peer holds the credential
    ResendLost,                     \* a Lost not answered is sent on every connection
    Until,                          \* a rotation's event is served before Lost
    GenBase,                        \* additions are taken only on the generation they extend
    SReconcile,                     \* a Pull's digest of S is compared: a member open on one side only gets Lost
    ByRoleOn,                       \* a judged holder is offered by role
    LostRetest,                     \* a member lost for a reason other than a credential change is pending again on both sides
    TestAtArrival,                  \* the test of a filter's arrival precedes every later message of the connection
    Hostile                         \* the peer may answer any Hit as accepted

A == "a"
Other(x, l) == CHOOSE y \in l : y # x
Rec0 == [rid |-> 0, stored |-> {}, gen |-> 0, sentGen |-> 0, ackedGen |-> 0, ackedPos |-> 0, sentPos |-> 0,
         testedPos |-> 0, testedGen |-> 0, open |-> FALSE, proof |-> "none", proofEp |-> 0, ending |-> FALSE,
         outst |-> FALSE, ackPend |-> 0, rejected |-> FALSE]
Node0(role, ep) == [ep |-> ep, view |-> "unknown", pos |-> IF ep > 0 THEN 1 ELSE 0,
                    changed |-> [c \in 1..MaxEp |-> IF c = ep THEN 1 ELSE 0], rec |-> Rec0]

VARIABLES st, role, removed, epoch, link, q, active, cloned, cnt
vars == <<st, role, removed, epoch, link, q, active, cloned, cnt>>

Init ==
    /\ st = [s \in Stores |-> IF s = A THEN Node0(RoleA, EpA) ELSE Node0(RoleB, EpB)]
    /\ role = [s \in Stores |-> IF s = A THEN RoleA ELSE RoleB]
    /\ removed = [s \in Stores |-> FALSE]
    /\ epoch = IF EpA > EpB THEN EpA ELSE EpB
    /\ link = {}
    /\ q = [s \in Stores |-> <<>>]
    /\ active = {A, "b"}
    /\ cloned = FALSE
    /\ cnt = [drop |-> 0, recloss |-> 0, clone |-> 0, rot |-> 0, remove |-> 0, grant |-> 0, rid |-> 0, hostile |-> 0, rotOpen |-> FALSE]

\* What a node's filter holds: its admissible credentials for this connection.
Creds(s) == IF s.view = "departed" \/ s.ep = 0 THEN {} ELSE {s.ep}
Pending(s) == {c \in Creds(s) : s.changed[c] > s.rec.ackedPos}
TestSet(s) == IF TestPending THEN Pending(s) ELSE {c \in Creds(s) : s.changed[c] > s.rec.testedPos}

\* The test a change or arrival runs: on the pending set against the stored filter.
Hits(s, stored) == IF s.rec.open THEN {} ELSE TestSet(s) \cap stored
Whole(s) == [t |-> "B", gen |-> s.rec.sentGen + 1, base |-> 0, adds |-> Creds(s), pos |-> s.pos]
Additions(s) ==
    [t |-> "B", gen |-> s.rec.sentGen + 1, base |-> s.rec.ackedGen,
     adds |-> {c \in Creds(s) : s.changed[c] > s.rec.ackedPos}, pos |-> s.pos]
Sent(s, b) == [s EXCEPT !.rec.sentGen = b.gen, !.rec.sentPos = b.pos]

Connect(x, y) ==
    LET same == st[x].rec.rid # 0 /\ st[x].rec.rid = st[y].rec.rid
        rid == cnt.rid + 1
        Fresh(s) == [s EXCEPT !.rec = [Rec0 EXCEPT !.rid = rid]]
        sx == IF same THEN st[x] ELSE Fresh(st[x])
        sy == IF same THEN st[y] ELSE Fresh(st[y])
        Msg(s) == IF same /\ s.rec.ackedGen > 0 THEN Additions(s) ELSE Whole(s)
        Losts(s) == IF s.rec.ending /\ ResendLost THEN <<[t |-> "Lost"]>> ELSE <<>>
    IN
    /\ link = {}
    /\ x \in active /\ y \in active
    /\ x = A /\ y # A
    /\ link' = {x, y}
    /\ st' = [st EXCEPT ![x] = Sent(sx, Msg(sx)), ![y] = Sent(sy, Msg(sy))]
    /\ q' = [q EXCEPT ![y] = <<Msg(sx)>> \o Losts(sx), ![x] = <<Msg(sy)>> \o Losts(sy)]
    /\ cnt' = IF same THEN cnt ELSE [cnt EXCEPT !.rid = rid]
    /\ UNCHANGED <<role, removed, epoch, active, cloned>>

Drop ==
    /\ link # {}
    /\ cnt.drop < MaxDrop
    /\ link' = {}
    /\ q' = [s \in Stores |-> <<>>]
    /\ st' = [s \in Stores |-> [st[s] EXCEPT !.rec.outst = FALSE, !.rec.ackPend = 0, !.rec.rejected = FALSE]]
    /\ cnt' = [cnt EXCEPT !.drop = @ + 1]
    /\ UNCHANGED <<role, removed, epoch, active, cloned>>

Loses(s) == s \notin link /\ s \in active /\ cnt.recloss < MaxRecLoss
LoseRecord(s) ==
    /\ Loses(s)
    /\ st' = [st EXCEPT ![s].rec = Rec0]
    /\ cnt' = [cnt EXCEPT !.recloss = @ + 1]
    /\ UNCHANGED <<role, removed, epoch, link, q, active, cloned>>

Clone ==
    /\ "c" \in Stores
    /\ cnt.clone < MaxClone
    /\ ~cloned
    /\ st' = [st EXCEPT !["c"] = st["b"]]
    /\ role' = [role EXCEPT !["c"] = role["b"]]
    /\ removed' = [removed EXCEPT !["c"] = removed["b"]]
    /\ cloned' = TRUE
    /\ cnt' = [cnt EXCEPT !.clone = @ + 1]
    /\ UNCHANGED <<epoch, link, q, active>>
Activate ==
    /\ cloned /\ "c" \notin active
    /\ active' = active \cup {"c"}
    /\ UNCHANGED <<st, role, removed, epoch, link, q, cloned, cnt>>

\* A credential change at n: pending from here on.
Touch(s, c) == [s EXCEPT !.pos = @ + 1, !.changed[c] = s.pos + 1]

\* Sends the additions a change makes; tested on the next Test.
SendAdd(n) ==
    LET s == st[n] b == Additions(s) IN
    /\ n \in link
    /\ \E c \in Creds(s) : s.changed[c] > s.rec.sentPos
    /\ s.rec.ackedGen > 0 \/ s.rec.sentGen > 0
    /\ st' = [st EXCEPT ![n] = Sent(@, b)]
    /\ q' = [q EXCEPT ![Other(n, link)] = Append(@, b)]
    /\ UNCHANGED <<role, removed, epoch, link, active, cloned, cnt>>

RecvB(n) ==
    LET m == Head(q[n]) p == Other(n, link) s == st[n] IN
    /\ n \in link
    /\ q[n] # <<>> /\ m.t = "B"
    /\ IF m.base = 0 \/ m.base = s.rec.gen \/ ~GenBase
       THEN LET st2 == IF m.base = 0 THEN m.adds ELSE s.rec.stored \cup m.adds
                hits == IF TestAtArrival /\ ~s.rec.outst THEN Hits(s, st2) ELSE {}
                hm == IF hits # {} THEN <<[t |-> "Hit", c |-> CHOOSE x \in hits : TRUE]>> ELSE <<>>
            IN
            /\ st' = [st EXCEPT ![n].rec.stored = st2, ![n].rec.gen = m.gen,
                                ![n].rec.testedGen = IF TestAtArrival /\ ~s.rec.outst THEN m.gen ELSE @,
                                ![n].rec.testedPos = IF TestAtArrival /\ ~s.rec.outst THEN s.pos ELSE @,
                                ![n].rec.outst = @ \/ hits # {}]
            /\ q' = [q EXCEPT ![n] = Tail(@),
                               ![p] = (@ \o <<[t |-> "Ack", gen |-> m.gen, pos |-> m.pos]>>) \o hm]
       ELSE /\ UNCHANGED st
            /\ q' = [q EXCEPT ![n] = Tail(@), ![p] = Append(@, [t |-> "Unk"])]
    /\ UNCHANGED <<role, removed, epoch, link, active, cloned, cnt>>

RecvAck(n) ==
    LET m == Head(q[n]) s == st[n] IN
    /\ n \in link
    /\ q[n] # <<>> /\ m.t = "Ack"
    /\ st' = [st EXCEPT
              ![n].rec.ackedGen = m.gen,
              ![n].rec.ackedPos = IF AckWaitsOffers /\ s.rec.outst THEN @ ELSE m.pos,
              ![n].rec.ackPend = IF AckWaitsOffers /\ s.rec.outst THEN m.pos ELSE @]
    /\ q' = [q EXCEPT ![n] = Tail(@)]
    /\ UNCHANGED <<role, removed, epoch, link, active, cloned, cnt>>

RecvUnk(n) ==
    LET m == Head(q[n]) p == Other(n, link) b == Whole(st[n]) IN
    /\ n \in link
    /\ q[n] # <<>> /\ m.t = "Unk"
    /\ st' = [st EXCEPT ![n] = Sent(@, b)]
    /\ q' = [q EXCEPT ![n] = Tail(@), ![p] = Append(@, b)]
    /\ UNCHANGED <<role, removed, epoch, link, active, cloned, cnt>>

Test(n) ==
    LET s == st[n] p == Other(n, link) hits == TestSet(s) \cap s.rec.stored IN
    /\ n \in link
    /\ ~s.rec.outst /\ ~s.rec.open
    /\ s.rec.testedPos # s.pos \/ s.rec.testedGen # s.rec.gen
    /\ st' = [st EXCEPT ![n].rec.outst = hits # {}, ![n].rec.testedPos = s.pos, ![n].rec.testedGen = s.rec.gen,
                        ![n].rec.rejected = IF hits # {} THEN FALSE ELSE @]
    /\ q' = IF hits # {} THEN [q EXCEPT ![p] = Append(@, [t |-> "Hit", c |-> CHOOSE x \in hits : TRUE])] ELSE q
    /\ UNCHANGED <<role, removed, epoch, link, active, cloned, cnt>>

RecvHit(n) ==
    LET m == Head(q[n]) p == Other(n, link) s == st[n] ok == m.c \in Creds(s) IN
    /\ n \in link
    /\ q[n] # <<>> /\ m.t = "Hit"
    /\ st' = IF ok THEN [st EXCEPT ![n].rec.open = TRUE, ![n].rec.proof = "cred", ![n].rec.proofEp = m.c,
                                   ![n].rec.ending = FALSE]
             ELSE st
    /\ q' = [q EXCEPT ![n] = Tail(@), ![p] = Append(@, [t |-> "Reply", ok |-> ok, c |-> m.c, tag |-> ok])]
    /\ UNCHANGED <<role, removed, epoch, link, active, cloned, cnt>>

RecvReply(n) ==
    LET m == Head(q[n]) s == st[n] ok == m.ok /\ (m.tag \/ ~TagCheck) /\ m.c \in Creds(s)
        waiting == IF ~ok /\ (s.rec.gen # s.rec.testedGen \/ s.pos # s.rec.testedPos) /\ ~s.rec.open THEN Hits(s, s.rec.stored) ELSE {} IN
    /\ n \in link
    /\ q[n] # <<>> /\ m.t = "Reply"
    /\ st' = [st EXCEPT
              ![n].rec.open = @ \/ ok,
              ![n].rec.proof = IF ok THEN "cred" ELSE @,
              ![n].rec.proofEp = IF ok THEN m.c ELSE @,
              ![n].rec.ackedPos = IF s.rec.ackPend > 0 /\ waiting = {} THEN s.rec.ackPend ELSE @,
              ![n].rec.ackPend = IF waiting = {} THEN 0 ELSE @,
              ![n].rec.testedGen = IF waiting # {} THEN s.rec.gen ELSE @,
              ![n].rec.testedPos = IF waiting # {} THEN s.pos ELSE @,
              ![n].rec.outst = waiting # {}]
    /\ q' = [q EXCEPT ![n] = Tail(@),
                      ![Other(n, link)] = IF waiting # {} THEN Append(@, [t |-> "Hit", c |-> CHOOSE x \in waiting : TRUE]) ELSE @]
    /\ UNCHANGED <<role, removed, epoch, link, active, cloned, cnt>>

\* An adversary peer answers a Hit "accepted" for a credential it lacks.
HostileReply(n) ==
    LET p == Other(n, link) IN
    /\ Hostile
    /\ n \in link
    /\ q[n] # <<>> /\ Head(q[n]).t = "Hit"
    /\ q' = [q EXCEPT ![n] = Tail(@),
                      ![p] = Append(@, [t |-> "Reply", ok |-> TRUE, c |-> Head(q[n]).c, tag |-> FALSE])]
    /\ UNCHANGED <<st, role, removed, epoch, link, active, cloned, cnt>>

\* The adversary peer's filter claims every credential.
HostileFilter(n) ==
    LET p == Other(n, link) IN
    /\ Hostile
    /\ n \in link /\ n # A /\ cnt.hostile = 0
    /\ cnt' = [cnt EXCEPT !.hostile = 1]
    /\ q' = [q EXCEPT ![p] = Append(@, [t |-> "B", gen |-> st[n].rec.sentGen + 1, base |-> 0, adds |-> 1..MaxEp, pos |-> 0])]
    /\ st' = [st EXCEPT ![n] = Sent(@, [gen |-> st[n].rec.sentGen + 1, pos |-> st[n].rec.sentPos])]
    /\ UNCHANGED <<role, removed, epoch, link, active, cloned>>

\* ByRole: the sender judges the peer a holder; the receiver's own judgment decides.
OfferRole(n) ==
    LET s == st[n] p == Other(n, link) IN
    /\ ByRoleOn
    /\ n \in link
    /\ ~s.rec.open /\ ~s.rec.outst /\ s.view = "holder" /\ s.ep > 0
    /\ ~s.rec.rejected
    /\ st' = [st EXCEPT ![n].rec.outst = TRUE]
    /\ q' = [q EXCEPT ![p] = Append(@, [t |-> "Role", cs |-> Creds(s)])]
    /\ UNCHANGED <<role, removed, epoch, link, active, cloned, cnt>>

RecvRole(n) ==
    LET m == Head(q[n]) p == Other(n, link) s == st[n]
        ok == s.ep > 0 /\ (s.view = "holder" \/ (m.cs \cap Creds(s) # {})) IN
    /\ n \in link
    /\ q[n] # <<>> /\ m.t = "Role"
    /\ st' = IF ok THEN [st EXCEPT ![n].rec.open = TRUE, ![n].rec.proof = "holder", ![n].rec.proofEp = s.ep,
                                   ![n].rec.ending = FALSE]
             ELSE st
    /\ q' = [q EXCEPT ![n] = Tail(@), ![p] = Append(@, [t |-> "RoleOk", ok |-> ok])]
    /\ UNCHANGED <<role, removed, epoch, link, active, cloned, cnt>>

RecvRoleOk(n) ==
    LET m == Head(q[n]) s == st[n] IN
    /\ n \in link
    /\ q[n] # <<>> /\ m.t = "RoleOk"
    /\ st' = [st EXCEPT ![n].rec.open = @ \/ m.ok,
                        ![n].rec.proof = IF m.ok THEN "holder" ELSE @,
                        ![n].rec.proofEp = IF m.ok THEN s.ep ELSE @,
                        ![n].rec.outst = FALSE,
                        ![n].rec.rejected = ~m.ok,
                        ![n].rec.ackedPos = IF s.rec.ackPend > 0 THEN s.rec.ackPend ELSE @,
                        ![n].rec.ackPend = 0]
    /\ q' = [q EXCEPT ![n] = Tail(@)]
    /\ UNCHANGED <<role, removed, epoch, link, active, cloned, cnt>>

\* The event that ends sharing: the open is judged again on what n holds.
Judge(n) ==
    LET s == st[n] p == Other(n, link)
        gone == s.view = "departed"
        stale == s.rec.proof = "cred" /\ s.rec.proofEp # s.ep /\ s.view # "holder"
        ready == gone \/ ~Until \/ st[p].ep = s.ep \/ removed[p]
    IN
    /\ n \in link
    /\ s.rec.open
    /\ gone \/ stale
    /\ ready
    /\ st' = [st EXCEPT ![n].rec.open = FALSE, ![n].rec.ending = TRUE]
    /\ q' = [q EXCEPT ![p] = Append(@, [t |-> "Lost"])]
    /\ UNCHANGED <<role, removed, epoch, link, active, cloned, cnt>>

RecvLost(n) ==
    LET m == Head(q[n]) p == Other(n, link) IN
    /\ n \in link
    /\ q[n] # <<>> /\ m.t = "Lost"
    /\ st' = [st EXCEPT ![n] = IF LostRetest /\ @.ep > 0
                                THEN [Touch(@, @.ep) EXCEPT !.rec.open = FALSE]
                                ELSE [@ EXCEPT !.rec.open = FALSE]]
    /\ q' = [q EXCEPT ![n] = Tail(@), ![p] = Append(@, [t |-> "LostOk"])]
    /\ UNCHANGED <<role, removed, epoch, link, active, cloned, cnt>>

RecvLostOk(n) ==
    /\ n \in link
    /\ q[n] # <<>> /\ Head(q[n]).t = "LostOk"
    /\ st' = [st EXCEPT ![n].rec.ending = FALSE]
    /\ q' = [q EXCEPT ![n] = Tail(@)]
    /\ UNCHANGED <<role, removed, epoch, link, active, cloned, cnt>>

\* Rotation at a holder: the next epoch; a peer with L open gets the event.
Rotate(n) ==
    /\ n \in active
    /\ cnt.rot < MaxRot /\ epoch < MaxEp
    /\ role[n] /\ st[n].ep = epoch
    /\ epoch' = epoch + 1
    /\ st' = [st EXCEPT ![n] = Touch([@ EXCEPT !.ep = epoch + 1], epoch + 1)]
    /\ cnt' = [cnt EXCEPT !.rot = @ + 1, !.rotOpen = @ \/ (n \in link /\ st[n].rec.open)]
    /\ UNCHANGED <<role, removed, link, q, active, cloned>>

\* The rotation event reaches the peer through an open connection (the `until` member).
DeliverRot(n) ==
    LET p == Other(n, link) IN
    /\ n \in link
    /\ st[n].rec.open
    /\ st[p].ep < st[n].ep /\ st[p].ep > 0
    /\ ~removed[p]
    /\ st' = [st EXCEPT ![p] = Touch([@ EXCEPT !.ep = st[n].ep], st[n].ep)]
    /\ UNCHANGED <<role, removed, epoch, link, q, active, cloned, cnt>>

Grant(n) ==
    /\ n \in active
    /\ cnt.grant < MaxGrant
    /\ ~role[n]
    /\ role' = [role EXCEPT ![n] = TRUE]
    /\ removed' = [removed EXCEPT ![n] = FALSE]
    /\ st' = [st EXCEPT ![n] = Touch([@ EXCEPT !.ep = epoch], epoch)]
    /\ cnt' = [cnt EXCEPT !.grant = @ + 1]
    /\ UNCHANGED <<epoch, link, q, active, cloned>>

\* A removal of n's actor from L's role. The peer learns it by LearnView.
Remove(n) ==
    /\ n \in active
    /\ cnt.remove < MaxRemove
    /\ role[n]
    /\ role' = [role EXCEPT ![n] = FALSE]
    /\ removed' = [removed EXCEPT ![n] = TRUE]
    /\ cnt' = [cnt EXCEPT !.remove = @ + 1]
    /\ UNCHANGED <<st, epoch, link, q, active, cloned>>

\* A node's view of its peer's actor, learned at any time from group data.
LearnView(n, p) ==
    LET v == IF removed[p] THEN "departed" ELSE IF role[p] THEN "holder" ELSE "unknown" IN
    /\ n \in active /\ p \in active /\ n # p
    /\ {n, p} \subseteq {A, "b"} \/ {n, p} \subseteq {A, "c"}
    /\ st[n].view # v
    /\ st' = [st EXCEPT ![n].view = v, ![n].rec.rejected = FALSE]
    /\ UNCHANGED <<role, removed, epoch, link, q, active, cloned, cnt>>

\* The digest on every Pull: one side holds L open, the other does not. FIFO: the
\* digest is seen after every reply sent before it.
Reconcile(n) ==
    LET p == Other(n, link) IN
    /\ SReconcile /\ ~Hostile
    /\ n \in link
    /\ q[n] = <<>> /\ q[p] = <<>>
    /\ st[n].rec.open /\ ~st[p].rec.open
    /\ q' = [q EXCEPT ![n] = Append(@, [t |-> "Lost"])]
    /\ st' = IF LostRetest /\ st[p].ep > 0 THEN [st EXCEPT ![p] = Touch(@, @.ep)] ELSE st
    /\ UNCHANGED <<role, removed, epoch, link, active, cloned, cnt>>

Honest ==
    \/ \E n \in Stores :
        \/ SendAdd(n) \/ RecvB(n) \/ RecvAck(n) \/ RecvUnk(n) \/ Test(n) \/ RecvHit(n) \/ RecvReply(n)
        \/ OfferRole(n) \/ RecvRole(n) \/ RecvRoleOk(n) \/ Judge(n) \/ RecvLost(n) \/ RecvLostOk(n)
        \/ DeliverRot(n) \/ Reconcile(n)
    \/ \E n, p \in Stores : LearnView(n, p)
    \/ \E y \in Stores : Connect(A, y)
    \/ Activate

Next ==
    \/ Honest
    \/ \E n \in Stores : Rotate(n) \/ Grant(n) \/ Remove(n) \/ LoseRecord(n) \/ HostileReply(n) \/ HostileFilter(n)
    \/ Clone
    \/ Drop

Spec == Init /\ [][Next]_vars /\ WF_vars(Honest)

\* Properties, in what the pair of nodes can observe. ------------------------
\* The rule on what each holds: judged from each node's view and credentials.
RuleAt(n, p) ==
    /\ st[n].ep > 0
    /\ st[n].view # "departed"
    /\ st[n].view = "holder" \/ st[n].ep = st[p].ep
\* Shared requires both sides' rules (each judges independently).
Rule(n, p) == RuleAt(n, p) /\ RuleAt(p, n)

Quiet ==
    /\ link # {}
    /\ \A n \in link :
        LET p == Other(n, link) s == st[n] IN
        /\ q[n] = <<>>
        /\ ~s.rec.outst
        /\ ~ENABLED Judge(n)
        /\ ~ENABLED Test(n)
        /\ ~ENABLED OfferRole(n)
        /\ ~ENABLED SendAdd(n)
        /\ ~ENABLED DeliverRot(n)
        /\ ~ENABLED Reconcile(n)
        /\ \A v \in {"departed","holder"} : ~ENABLED LearnView(n, p)
        /\ s.rec.open \/ ~s.rec.ending \/ ~ResendLost

\* (1, 3) Once quiet, the pair share L exactly when the rule says so.
RuleHolds ==
    Quiet =>
      \A n \in link : LET p == Other(n, link) IN
        st[n].rec.open <=> (Rule(n, p) /\ (st[n].view # "unknown" \/ st[p].view # "unknown" \/ st[n].ep = st[p].ep))

\* (3) A node whose own removal the server has learned is not left open: the
\* judgment holds for every quiet state whichever connection, gain or loss.
\* (3) A holder that an open connection served reaches the rotation's epoch.
EpochReached == Quiet /\ cnt.rotOpen => \A n \in link : ~removed[n] /\ st[n].ep > 0 => st[n].ep = epoch
Settled == Quiet
Settles == <>[]Settled
====
