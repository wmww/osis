---- MODULE NetBlind ----
(* A reader "a" and a peer "b" that cannot read: issues/net-reconnect.md (Peers that
   cannot read). a opens L by the sync key on each connection; b tests nothing, keeps no
   record, never pulls and judges nothing. a pulls b's log, uploads what the last Pull
   did not show, and deletes what it covers (retention: a right holder's covering
   snapshot, sent as the ordinary signed Delete). e1 is a body, s the snapshot covering
   it. b's store may be restored from a backup; a's record may be lost. *)
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    MaxDrop, MaxRestore, MaxRecLoss,
    KnowFromPull,                   \* a's knowledge of b comes only from Pull replies, never an upload's ack
    WholeResets,                    \* a from-the-start reply replaces that knowledge
    CoverFirst,                     \* a deletes only once a Pull showed the covering snapshot at b
    FromKnown                       \* a deletes whatever a Pull shows that it covers, not only at the moment of covering

Inf == 99
Entries == {"e1", "s"}
Blob0 == [log |-> {}, end |-> 0, held |-> {}, tomb |-> {}, inc |-> 1, draws |-> 0, pend |-> FALSE, hist |-> {[inc |-> 1, end |-> Inf]}]
NoCur == [inc |-> 0, pos |-> 0]

VARIABLES
    b, bak,                         \* b's store, the backup it may be restored from
    a,                              \* a's store and its record of b: held, cover, cur, atb (what Pulls showed)
    link, up, down,                 \* connection, a->b and b->a queues
    sent, pulled,                   \* per connection: uploads sent, a Pull answered
    written, cnt, badDelete
vars == <<b, bak, a, link, up, down, sent, pulled, written, cnt, badDelete>>

A0 == [held |-> {}, cover |-> {}, cur |-> NoCur, atb |-> {}]

Init ==
    /\ b = Blob0 /\ bak = Blob0
    /\ a = A0
    /\ link = FALSE /\ up = <<>> /\ down = <<>>
    /\ sent = {} /\ pulled = FALSE
    /\ written = {}
    /\ cnt = [drop |-> 0, restore |-> 0, recloss |-> 0]
    /\ badDelete = FALSE

Drawn(s) ==
    IF ~s.pend THEN s
    ELSE LET i == 10 + s.draws IN
         [s EXCEPT !.inc = i, !.draws = @ + 1, !.pend = FALSE,
                   !.hist = {IF h.inc = s.inc THEN [inc |-> h.inc, end |-> s.end] ELSE h : h \in @}
                            \cup {[inc |-> i, end |-> Inf]}]
Log(s0, k, e) ==
    LET s == Drawn(s0) IN
    [s EXCEPT !.log = {ev \in @ : ev.e # e} \cup {[pos |-> s.end + 1, k |-> k, e |-> e]}, !.end = @ + 1]
Valid(c, s) == c # NoCur /\ c.pos <= s.end /\ \E h \in s.hist : h.inc = c.inc /\ c.pos <= h.end

Write(e) ==
    /\ e \notin written
    /\ e = "s" => "e1" \in written
    /\ written' = written \cup {e}
    /\ a' = [a EXCEPT !.held = @ \cup {e}]
    /\ UNCHANGED <<b, bak, link, up, down, sent, pulled, cnt, badDelete>>

\* a holds the covering snapshot: e1 is covered, a drops it.
Cover ==
    /\ "s" \in a.held /\ "e1" \in a.held
    /\ a' = [a EXCEPT !.held = @ \ {"e1"}, !.cover = @ \cup {"e1"}]
    /\ up' = IF ~FromKnown /\ link /\ "e1" \in a.atb /\ (~CoverFirst \/ "s" \in a.atb)
             THEN Append(up, [t |-> "Del", e |-> "e1"]) ELSE up
    /\ UNCHANGED <<b, bak, link, down, sent, pulled, written, cnt, badDelete>>

Connect ==
    /\ ~link
    /\ link' = TRUE
    /\ up' = <<[t |-> "Open"]>>
    /\ sent' = {} /\ pulled' = FALSE
    /\ UNCHANGED <<b, bak, a, down, written, cnt, badDelete>>

Drop ==
    /\ link /\ cnt.drop < MaxDrop
    /\ link' = FALSE /\ up' = <<>> /\ down' = <<>>
    /\ cnt' = [cnt EXCEPT !.drop = @ + 1]
    /\ UNCHANGED <<b, bak, a, sent, pulled, written, badDelete>>

Pull ==
    /\ link /\ up = <<>> /\ down = <<>>
    /\ ~pulled \/ a.cur # [inc |-> b.inc, pos |-> b.end]   \* first Pull of a connection, or a push announced a change
    /\ up' = <<[t |-> "Pull", cur |-> a.cur]>>
    /\ UNCHANGED <<b, bak, a, link, down, sent, pulled, written, cnt, badDelete>>

RecvOpen ==
    /\ link /\ up # <<>> /\ Head(up).t = "Open"
    /\ up' = Tail(up)
    /\ UNCHANGED <<b, bak, a, link, down, sent, pulled, written, cnt, badDelete>>

RecvPull ==
    LET m == Head(up) ok == Valid(m.cur, b)
        evs == {ev \in b.log : ~ok \/ ev.pos > m.cur.pos} IN
    /\ link /\ up # <<>> /\ m.t = "Pull"
    /\ up' = Tail(up)
    /\ down' = Append(down, [t |-> "Reply", evs |-> evs, whole |-> ~ok, cur |-> [inc |-> b.inc, pos |-> b.end]])
    /\ UNCHANGED <<b, bak, a, link, sent, pulled, written, cnt, badDelete>>

ApplyReply ==
    LET m == Head(down)
        base == IF m.whole /\ WholeResets THEN {} ELSE a.atb
        adds == {ev.e : ev \in {x \in m.evs : x.k = "add"}}
        dels == {ev.e : ev \in {x \in m.evs : x.k = "del"}} IN
    /\ link /\ down # <<>> /\ m.t = "Reply"
    /\ down' = Tail(down)
    /\ a' = [a EXCEPT !.cur = m.cur, !.atb = (base \cup adds) \ dels]
    /\ pulled' = TRUE
    /\ UNCHANGED <<b, bak, link, up, sent, written, cnt, badDelete>>

Upload(e) ==
    /\ link /\ e \in a.held /\ e \notin a.atb /\ e \notin sent /\ pulled
    /\ up' = Append(up, [t |-> "Up", e |-> e])
    /\ sent' = sent \cup {e}
    /\ UNCHANGED <<b, bak, a, link, down, pulled, written, cnt, badDelete>>

RecvUp ==
    LET m == Head(up) IN
    /\ link /\ up # <<>> /\ m.t = "Up"
    /\ up' = Tail(up)
    /\ b' = IF m.e \in b.held \/ m.e \in b.tomb THEN b
            ELSE [Log(b, "add", m.e) EXCEPT !.held = @ \cup {m.e}]
    /\ down' = Append(down, [t |-> "UpOk", e |-> m.e])
    /\ UNCHANGED <<bak, a, link, sent, pulled, written, cnt, badDelete>>

RecvUpOk ==
    LET m == Head(down) IN
    /\ link /\ down # <<>> /\ m.t = "UpOk"
    /\ down' = Tail(down)
    /\ a' = IF KnowFromPull THEN a ELSE [a EXCEPT !.atb = @ \cup {m.e}]
    /\ UNCHANGED <<b, bak, link, up, sent, pulled, written, cnt, badDelete>>

\* A right holder's delete: what a covers, b still shows, and a Pull shows carried.
Delete ==
    /\ FromKnown /\ link /\ pulled
    /\ "e1" \in a.cover /\ "e1" \in a.atb /\ "del" \notin sent
    /\ ~CoverFirst \/ "s" \in a.atb
    /\ up' = Append(up, [t |-> "Del", e |-> "e1"])
    /\ sent' = sent \cup {"del"}
    /\ UNCHANGED <<b, bak, a, link, down, pulled, written, cnt, badDelete>>

RecvDel ==
    LET m == Head(up) IN
    /\ link /\ up # <<>> /\ m.t = "Del"
    /\ up' = Tail(up)
    /\ b' = IF m.e \in b.held
            THEN [Log(b, "del", m.e) EXCEPT !.held = @ \ {m.e}, !.tomb = @ \cup {m.e}]
            ELSE [b EXCEPT !.tomb = @ \cup {m.e}]
    /\ badDelete' = (badDelete \/ (m.e \in b.held /\ "s" \notin b.held))
    /\ UNCHANGED <<bak, a, link, down, sent, pulled, written, cnt>>

Backup ==
    /\ cnt.restore < MaxRestore /\ bak # b
    /\ bak' = b
    /\ UNCHANGED <<b, a, link, up, down, sent, pulled, written, cnt, badDelete>>

Restore ==
    /\ ~link /\ cnt.restore < MaxRestore
    /\ b' = [bak EXCEPT !.pend = TRUE, !.draws = b.draws + 1]
    /\ cnt' = [cnt EXCEPT !.restore = @ + 1]
    /\ UNCHANGED <<bak, a, link, up, down, sent, pulled, written, badDelete>>

LoseRecord ==
    /\ ~link /\ cnt.recloss < MaxRecLoss
    /\ a' = [a EXCEPT !.cur = NoCur, !.atb = {}]
    /\ cnt' = [cnt EXCEPT !.recloss = @ + 1]
    /\ UNCHANGED <<b, bak, link, up, down, sent, pulled, written, badDelete>>

Honest ==
    \/ Connect \/ Pull \/ RecvOpen \/ RecvPull \/ ApplyReply \/ RecvUp \/ RecvUpOk \/ RecvDel \/ Delete
    \/ \E e \in Entries : Upload(e)
Next ==
    \/ Honest \/ Cover \/ Drop \/ Backup \/ Restore \/ LoseRecord
    \/ \E e \in Entries : Write(e)
Spec == Init /\ [][Next]_vars /\ WF_vars(Honest)

Quiet ==
    /\ link /\ pulled /\ up = <<>> /\ down = <<>>
    /\ a.cur = [inc |-> b.inc, pos |-> b.end]
    /\ ~\E e \in Entries : ENABLED Upload(e)
    /\ ~ENABLED Delete

\* A delete at b never takes a body whose covering snapshot b does not hold.
Carried == ~badDelete
\* Quiet: b holds what a holds live.
Placed == Quiet => a.held \subseteq b.held
\* Quiet: b holds nothing a has covered: a delete reaches a peer that cannot read,
\* however long it was away and whether or not a remembers deleting it.
DeletesReach == Quiet => a.cover \cap b.held = {}
Settles == <>[]Quiet
====
