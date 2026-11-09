---- MODULE NetStream ----
(* The data half of issues/net-reconnect.md: a node-wide log, opaque cursors,
   one Pull per side of a connection, joins, Lost and lag, restarts, record
   loss, deletion-event expiry, restored or copied stores, and `Synced`. Node
   "a" talks to one peer node: "b", or "c", a copy of b's store taken at some
   instant. A rule of the design is a flag; turning it off must break a
   property. The shared set is NetShared.tla: here who may open is the ghost
   `rights`. *)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Entries, Ls, EL, Author,        \* entries, sync IDs, an entry's sync ID, its writer
    PageK,                          \* events per reply page
    Stores, Dials,                  \* {"a","b"} or {"a","b","c"}; <<dialer, listener>> pairs allowed
    MaxRestart, MaxRecLoss, MaxDelete, MaxExpire, MaxClone, MaxDrop, MaxRevoke,
    Retire,                         \* the copy replaces b (a restore) or runs beside it
    IncCheck,                       \* a cursor is honoured only on this store's own history (proposed)
    KeepHistory,                    \* a start records the incarnation before it, so a restart honours earlier cursors
    HorizonMode,                    \* "oldest" (issue's text) | "trim" (position of the newest dropped deletion)
    Infer,                          \* "literal" (issue) | "knew" (spec/sync.md §6) | "none" (proposed)
    JoinDurable,                    \* an unfinished join keeps its own position until its last page
    JoinAnswer,                     \* a join of what the server does not share is answered, not an empty success
    LostOlder,                      \* Lost keeps an older lag
    CursorOnApply,                  \* the stored cursor advances only with the applied reply
    ServerGate,                     \* each reply is judged on the server's S now
    BothPull,                       \* the listener pulls too
    SReconcile,                     \* a Pull's member set is compared with the server's S (a digest on the wire); a member the server does not share is answered as Lost
    Rearm                           \* a change announced during a Pull denies that Pull's caught-up

A == "a"
Other(x, l) == CHOOSE y \in l : y # x
Inf == 99
NoCur == [lid |-> 0, inc |-> 0, pos |-> 0]
Older(c1, c2) == IF c1.pos < c2.pos THEN c1 ELSE c2

Mem0 == [st |-> "out", c |-> NoCur]
Rec0 == [rid |-> 0, cur |-> NoCur, mem |-> [l \in Ls |-> Mem0], srv |-> [l \in Ls |-> FALSE],
         lostp |-> {}, listing |-> [on |-> FALSE, seen |-> {}], knew |-> {}, last |-> NoCur, everCur |-> FALSE]
Store0(lid, inc) == [log |-> {}, end |-> 0, held |-> {}, tomb |-> {}, lid |-> lid, inc |-> inc,
                     hist |-> {[inc |-> inc, end |-> Inf]}, floor |-> 0, rec |-> Rec0]
NoReply == [on |-> FALSE, items |-> {}, whole |-> FALSE, listing |-> FALSE, more |-> FALSE, cur |-> NoCur, refused |-> {}, stale |-> FALSE, reqcur |-> NoCur, asked |-> {}]

VARIABLES st, link, dialer, inflight, active, cloned, cu, dirty, ever, written,
          rights, cnt, unforced, lostW, badServe
vars == <<st, link, dialer, inflight, active, cloned, cu, dirty, ever, written, rights, cnt, unforced, lostW, badServe>>

Init ==
    /\ st = [s \in Stores |-> IF s = "a" THEN Store0(1, 1) ELSE Store0(2, 2)]
    /\ link = {}
    /\ dialer = A
    /\ inflight = [s \in Stores |-> NoReply]
    /\ active = {A, "b"}
    /\ cloned = FALSE
    /\ cu = [s \in Stores |-> [l \in Ls |-> FALSE]]
    /\ dirty = [s \in Stores |-> FALSE]
    /\ ever = {}
    /\ written = {}
    /\ rights = [s \in Stores |-> [l \in Ls |-> TRUE]]
    /\ cnt = [restart |-> 0, recloss |-> 0, delete |-> 0, expire |-> 0, clone |-> 0, drop |-> 0, revoke |-> 0, inc |-> 2, rid |-> 0]
    /\ unforced = FALSE
    /\ lostW = {}
    /\ badServe = FALSE

\* Logging ------------------------------------------------------------------
Drop_e(lg, e) == {ev \in lg : ev.e # e}
LogAdd(s, e) ==
    IF e \in s.held \/ e \in s.tomb THEN s
    ELSE [s EXCEPT !.log = Drop_e(@, e) \cup {[pos |-> s.end + 1, k |-> "add", e |-> e]},
                   !.end = @ + 1, !.held = @ \cup {e}]
LogDel(s, e) ==
    IF e \in s.held
    THEN [s EXCEPT !.log = Drop_e(@, e) \cup {[pos |-> s.end + 1, k |-> "del", e |-> e]},
                   !.end = @ + 1, !.held = @ \ {e}, !.tomb = @ \cup {e}]
    ELSE [s EXCEPT !.tomb = @ \cup {e}]
RECURSIVE Fold(_, _)
Fold(s, its) ==
    IF its = {} THEN s
    ELSE LET i == CHOOSE x \in its : TRUE
         IN Fold(IF i.k = "add" THEN LogAdd(s, i.e) ELSE LogDel(s, i.e), its \ {i})

\* Serving ------------------------------------------------------------------
Dels(s) == {ev \in s.log : ev.k = "del"}
MinPos(S) == CHOOSE p \in {ev.pos : ev \in S} : \A ev \in S : p <= ev.pos
Horizon(s) ==
    IF HorizonMode = "oldest"
    THEN IF Dels(s) = {} THEN s.end ELSE MinPos(Dels(s))
    ELSE s.floor
Lineage(c, s) == \E h \in s.hist : h.inc = c.inc /\ c.pos <= h.end
Valid(c, s) ==
    /\ c # NoCur /\ c.lid = s.lid /\ c.pos <= s.end
    /\ c.pos >= Horizon(s)
    /\ (IncCheck => Lineage(c, s))
\* Real need for a from-the-start reply: nothing to resume from, a deletion the
\* log really dropped above the cursor, or a restored or copied store's other
\* history. An ordinary restart is none of these: it never forces one.
Forced(r, s) ==
    \/ r.cur = NoCur /\ ~r.everCur
    \/ r.cur # NoCur /\ (r.cur.lid # s.lid \/ r.cur.pos < s.floor
                          \/ (cloned /\ (r.cur.pos > s.end \/ ~Lineage(r.cur, s))))

Page(S) == {ev \in S : Cardinality({u \in S : u.pos < ev.pos}) < PageK}

Pull(x) ==
    LET y == Other(x, link)
        r == st[x].rec
        s == st[y]
        cv == Valid(r.cur, s)
        wholeNew == ~cv
        From(l) ==
            IF wholeNew THEN 0
            ELSE IF r.mem[l].st = "join"
                 THEN IF Valid(r.mem[l].c, s) THEN r.mem[l].c.pos ELSE 0
                 ELSE r.cur.pos
        Shared(l) == r.mem[l].st # "out" /\ (s.rec.srv[l] \/ ~ServerGate)
        all == {ev \in s.log : Shared(EL[ev.e]) /\ ev.pos > From(EL[ev.e])}
        pg == Page(all)
        more == pg # all
        p == IF more THEN CHOOSE q \in {ev.pos : ev \in pg} : \A ev \in pg : ev.pos <= q ELSE s.end
        refused == {l \in Ls : ~s.rec.srv[l] /\ (r.mem[l].st = "join" \/ (r.mem[l].st = "stream" /\ SReconcile))}
    IN
    /\ x \in link
    /\ ~inflight[x].on
    /\ x = dialer \/ BothPull
    /\ \E l \in Ls : r.mem[l].st # "out" /\ ~cu[x][l]
    /\ inflight' = [inflight EXCEPT ![x] =
            [on |-> TRUE, items |-> {[k |-> ev.k, e |-> ev.e] : ev \in pg},
             whole |-> wholeNew, listing |-> wholeNew \/ r.listing.on, more |-> more,
             cur |-> [lid |-> s.lid, inc |-> s.inc, pos |-> p], refused |-> refused, stale |-> FALSE, reqcur |-> r.cur, asked |-> {l \in Ls : r.mem[l].st # "out"}]]
    /\ st' = [st EXCEPT ![y].rec.last = r.cur,
                        ![x].rec.cur = IF CursorOnApply THEN @ ELSE inflight'[x].cur,
                        ![x].rec.everCur = IF CursorOnApply THEN @ ELSE TRUE]
    /\ unforced' = (unforced \/ (wholeNew /\ ~r.listing.on /\ ~Forced(r, s)))
    /\ badServe' = (badServe \/ \E ev \in pg : ~rights[x][EL[ev.e]])
    /\ UNCHANGED <<link, dialer, active, cloned, cu, dirty, ever, written, rights, cnt, lostW>>

Apply(x) ==
    LET y == Other(x, link)
        rp == inflight[x]
        r == st[x].rec
        s1 == Fold(st[x], rp.items)
        listing2 == IF rp.whole THEN [on |-> TRUE, seen |-> {i.e : i \in rp.items}]
                    ELSE IF r.listing.on THEN [r.listing EXCEPT !.seen = @ \cup {i.e : i \in rp.items}]
                    ELSE r.listing
        lastPage == rp.listing /\ ~rp.more
        Member(e) == r.mem[EL[e]].st # "out"
        candidates ==
            IF Infer = "none" \/ ~lastPage THEN {}
            ELSE IF Infer = "literal"
                 THEN {e \in s1.held : Member(e) /\ e \notin listing2.seen}
                 ELSE {e \in s1.held : Member(e) /\ e \notin listing2.seen /\ e \in r.knew}
        s2 == Fold(s1, {[k |-> "del", e |-> e] : e \in candidates})
        Mem2(l) ==
            LET m == r.mem[l] IN
            IF l \in rp.refused /\ m.st = "stream" THEN [st |-> "out", c |-> rp.reqcur]
            ELSE IF l \in rp.refused /\ JoinAnswer THEN [st |-> "out", c |-> m.c]
            ELSE IF m.st = "out" \/ l \notin rp.asked THEN m
            ELSE IF m.st = "join" /\ rp.more /\ JoinDurable /\ ~rp.whole THEN [st |-> "join", c |-> rp.cur]
            ELSE [st |-> "stream", c |-> NoCur]
        mem2 == [l \in Ls |-> Mem2(l)]
    IN
    /\ x \in link
    /\ inflight[x].on
    /\ inflight' = [inflight EXCEPT ![x] = NoReply]
    /\ st' = [st EXCEPT
              ![x] = [s2 EXCEPT
                !.rec.cur = IF ~CursorOnApply THEN @ ELSE IF rp.whole \/ rp.cur.pos > r.cur.pos THEN rp.cur ELSE r.cur,
                !.rec.everCur = TRUE,
                !.rec.mem = mem2,
                !.rec.listing = IF rp.more THEN listing2 ELSE [on |-> FALSE, seen |-> {}],
                !.rec.knew = @ \cup {i.e : i \in rp.items}],
              ![y].rec.last = rp.cur]
    /\ cu' = [cu EXCEPT ![x] = [l \in Ls |-> ~rp.more /\ ~(Rearm /\ rp.stale) /\ mem2[l].st = "stream" /\ l \in rp.asked]]
    /\ dirty' = [dirty EXCEPT ![x] = @ \/ s2.end # st[x].end]
    /\ lostW' = lostW \cup (candidates \ ever)
    /\ UNCHANGED <<link, dialer, active, cloned, ever, written, rights, cnt, unforced, badServe>>

\* A push on the connection: whoever holds a change tells the peer's follow.
Notify(x) ==
    LET y == Other(x, link) IN
    /\ x \in link
    /\ dirty[y]
    /\ dirty' = [dirty EXCEPT ![y] = FALSE]
    /\ cu' = [cu EXCEPT ![x] = [l \in Ls |-> FALSE]]
    /\ inflight' = [inflight EXCEPT ![x].stale = @ \/ inflight[x].on]
    /\ UNCHANGED <<st, link, dialer, active, cloned, ever, written, rights, cnt, unforced, lostW, badServe>>

\* The shared set, abstracted ------------------------------------------------
Open(y, l) ==
    LET x == Other(y, link) IN
    /\ y \in link
    /\ rights[x][l]
    /\ ~st[y].rec.srv[l]
    /\ st[y].rec.lostp = {}
    /\ st' = [st EXCEPT ![y].rec.srv[l] = TRUE]
    /\ UNCHANGED <<link, dialer, inflight, active, cloned, cu, dirty, ever, written, rights, cnt, unforced, lostW, badServe>>

Join(x, l) ==
    LET y == Other(x, link) IN
    /\ x \in link
    /\ st[y].rec.srv[l]
    /\ st[x].rec.mem[l].st = "out"
    /\ st' = [st EXCEPT ![x].rec.mem[l].st = "join"]
    /\ cu' = [cu EXCEPT ![x][l] = FALSE]
    /\ UNCHANGED <<link, dialer, inflight, active, cloned, dirty, ever, written, rights, cnt, unforced, lostW, badServe>>

Revoke(x, l) ==
    LET y == Other(x, link) IN
    /\ x \in link
    /\ cnt.revoke < MaxRevoke
    /\ rights[x][l]
    /\ st[y].rec.srv[l]
    /\ rights' = [rights EXCEPT ![x][l] = FALSE]
    /\ st' = [st EXCEPT ![y].rec.srv[l] = FALSE,
                        ![y].rec.lostp = @ \cup {[l |-> l, c |-> st[y].rec.last]}]
    /\ cnt' = [cnt EXCEPT !.revoke = @ + 1]
    /\ UNCHANGED <<link, dialer, inflight, active, cloned, cu, dirty, ever, written, unforced, lostW, badServe>>

Regrant(x, l) ==
    /\ ~rights[x][l]
    /\ rights' = [rights EXCEPT ![x][l] = TRUE]
    /\ UNCHANGED <<st, link, dialer, inflight, active, cloned, cu, dirty, ever, written, cnt, unforced, lostW, badServe>>

\* `Lost` is written in order after the replies before it.
DeliverLost(x) ==
    LET y == Other(x, link) IN
    /\ x \in link
    /\ ~inflight[x].on
    /\ \E it \in st[y].rec.lostp :
        LET m == st[x].rec.mem[it.l]
            c2 == IF m.st = "stream" THEN it.c
                  ELSE IF LostOlder THEN Older(m.c, it.c) ELSE it.c
        IN
        /\ st' = [st EXCEPT ![y].rec.lostp = @ \ {it},
                            ![x].rec.mem[it.l] = [st |-> "out", c |-> c2]]
        /\ cu' = [cu EXCEPT ![x][it.l] = FALSE]
    /\ UNCHANGED <<link, dialer, inflight, active, cloned, dirty, ever, written, rights, cnt, unforced, lostW, badServe>>

\* Local events -------------------------------------------------------------
Write(s, e) ==
    /\ s \in active
    /\ e \notin written
    /\ Author[e] = s \/ (Author[e] = "b" /\ s = "c")
    /\ st' = [st EXCEPT ![s] = LogAdd(@, e)]
    /\ written' = written \cup {e}
    /\ dirty' = [dirty EXCEPT ![s] = s \in link]
    /\ UNCHANGED <<link, dialer, inflight, active, cloned, cu, ever, rights, cnt, unforced, lostW, badServe>>

Delete(s, e) ==
    /\ s \in active
    /\ cnt.delete < MaxDelete
    /\ e \in st[s].held
    /\ st' = [st EXCEPT ![s] = LogDel(@, e)]
    /\ ever' = ever \cup {e}
    /\ cnt' = [cnt EXCEPT !.delete = @ + 1]
    /\ dirty' = [dirty EXCEPT ![s] = s \in link]
    /\ UNCHANGED <<link, dialer, inflight, active, cloned, cu, written, rights, unforced, lostW, badServe>>

\* TOMBSTONE_LIFETIME passes for the oldest deletion event. Unfair.
Expire(s) ==
    /\ s \in active
    /\ cnt.expire < MaxExpire
    /\ Dels(st[s]) # {}
    /\ LET ev == CHOOSE d \in Dels(st[s]) : d.pos = MinPos(Dels(st[s]))
       IN st' = [st EXCEPT ![s].log = @ \ {ev}, ![s].tomb = @ \ {ev.e},
                           ![s].floor = ev.pos]
    /\ cnt' = [cnt EXCEPT !.expire = @ + 1]
    /\ UNCHANGED <<link, dialer, inflight, active, cloned, cu, dirty, ever, written, rights, unforced, lostW, badServe>>

\* A start: every start is a new incarnation of the store.
NewInc(s, i) ==
    [s EXCEPT !.inc = i,
              !.hist = IF KeepHistory
                       THEN {IF h.inc = s.inc THEN [inc |-> h.inc, end |-> s.end] ELSE h : h \in @}
                            \cup {[inc |-> i, end |-> Inf]}
                       ELSE {[inc |-> i, end |-> Inf]}]

Drop ==
    /\ link # {}
    /\ cnt.drop < MaxDrop
    /\ link' = {}
    /\ inflight' = [s \in Stores |-> NoReply]
    /\ cu' = [s \in Stores |-> [l \in Ls |-> FALSE]]
    /\ dirty' = [s \in Stores |-> FALSE]
    /\ cnt' = [cnt EXCEPT !.drop = @ + 1]
    /\ UNCHANGED <<st, dialer, active, cloned, ever, written, rights, unforced, lostW, badServe>>

Restart(s) ==
    /\ s \in active
    /\ cnt.restart < MaxRestart
    /\ st' = [st EXCEPT ![s] = NewInc(@, cnt.inc + 1)]
    /\ cnt' = [cnt EXCEPT !.restart = @ + 1, !.inc = @ + 1]
    /\ IF s \in link
       THEN /\ link' = {}
            /\ inflight' = [z \in Stores |-> NoReply]
            /\ cu' = [z \in Stores |-> [l \in Ls |-> FALSE]]
            /\ dirty' = [z \in Stores |-> FALSE]
       ELSE UNCHANGED <<link, inflight, cu, dirty>>
    /\ UNCHANGED <<dialer, active, cloned, ever, written, rights, unforced, lostW, badServe>>

LoseRecord(s) ==
    /\ s \in active
    /\ s \notin link
    /\ cnt.recloss < MaxRecLoss
    /\ st' = [st EXCEPT ![s].rec = Rec0]
    /\ cnt' = [cnt EXCEPT !.recloss = @ + 1]
    /\ UNCHANGED <<link, dialer, inflight, active, cloned, cu, dirty, ever, written, rights, unforced, lostW, badServe>>

\* The copy is taken at any instant, restored or started later.
Clone ==
    /\ "c" \in Stores
    /\ cnt.clone < MaxClone
    /\ ~cloned
    /\ st' = [st EXCEPT !["c"] = st["b"]]
    /\ cloned' = TRUE
    /\ cnt' = [cnt EXCEPT !.clone = @ + 1]
    /\ UNCHANGED <<link, dialer, inflight, active, cu, dirty, ever, written, rights, unforced, lostW, badServe>>

Activate ==
    /\ cloned
    /\ "c" \notin active
    /\ st' = [st EXCEPT !["c"] = NewInc(@, cnt.inc + 1)]
    /\ cnt' = [cnt EXCEPT !.inc = @ + 1]
    /\ active' = IF Retire THEN (active \ {"b"}) \cup {"c"} ELSE active \cup {"c"}
    /\ IF Retire /\ "b" \in link
       THEN /\ link' = {}
            /\ inflight' = [z \in Stores |-> NoReply]
            /\ cu' = [z \in Stores |-> [l \in Ls |-> FALSE]]
            /\ dirty' = [z \in Stores |-> FALSE]
       ELSE UNCHANGED <<link, inflight, cu, dirty>>
    /\ UNCHANGED <<dialer, cloned, ever, written, rights, unforced, lostW, badServe>>

Connect(x, y) ==
    LET same == st[x].rec.rid # 0 /\ st[x].rec.rid = st[y].rec.rid
        rid == cnt.rid + 1
        Fresh(s) == [s EXCEPT !.rec = [Rec0 EXCEPT !.rid = rid]]
    IN
    /\ link = {}
    /\ x \in active /\ y \in active
    /\ <<x, y>> \in Dials
    /\ link' = {x, y}
    /\ dialer' = x
    /\ IF same
       THEN UNCHANGED <<st, cnt>>
       ELSE /\ st' = [st EXCEPT ![x] = Fresh(@), ![y] = Fresh(@)]
            /\ cnt' = [cnt EXCEPT !.rid = rid]
    /\ UNCHANGED <<inflight, active, cloned, cu, dirty, ever, written, rights, unforced, lostW, badServe>>

Honest ==
    \/ \E s \in Stores : Pull(s) \/ Apply(s) \/ Notify(s) \/ DeliverLost(s)
    \/ \E s \in Stores, l \in Ls : Open(s, l) \/ Join(s, l) \/ Regrant(s, l)
    \/ \E s \in Stores, e \in Entries : Write(s, e)
    \/ Activate
    \/ \E p \in Dials : Connect(p[1], p[2])

Next ==
    \/ Honest
    \/ \E s \in Stores, e \in Entries : Delete(s, e)
    \/ \E s \in Stores, l \in Ls : Revoke(s, l)
    \/ \E s \in Stores : Expire(s) \/ Restart(s) \/ LoseRecord(s)
    \/ Clone
    \/ Drop

Spec == Init /\ [][Next]_vars /\ WF_vars(Honest)

\* Properties, in what a node can observe -------------------------------------
\* (1, 2) No node drops a write nobody deleted.
NoWriteLost == lostW = {}

\* (1, 4) `Synced` per source: L open, caught up, nothing announced. What the
\* source holds of L this node holds, or it was deleted somewhere (a deleted
\* entry a long-absent node keeps is retention's, not sync's).
CaughtUpHolds ==
    \A x \in link : LET y == Other(x, link) IN
      \A l \in Ls :
        (st[x].rec.mem[l].st = "stream" /\ cu[x][l] /\ ~dirty[y]
         /\ st[y].rec.srv[l] /\ ~inflight[x].on)
        => \A e \in st[y].held : EL[e] = l => (e \in st[x].held \/ e \in ever)

\* (3) Nothing is served for a sync ID the node has lost the right to.
ServedRight == ~badServe

\* (6) A from-the-start reply happens only when the record or the history is
\* really gone: an ordinary reconnect sends the changes.
ReconnectCost == ~unforced

\* Settling: the connection, all opens and pulls done.
Settled ==
    /\ link # {}
    /\ \A x \in link : LET y == Other(x, link) IN
        /\ ~inflight[x].on
        /\ st[y].rec.lostp = {}
        /\ \A l \in Ls : rights[x][l] => st[x].rec.mem[l].st = "stream" /\ cu[x][l]
Settles == <>[]Settled
====
