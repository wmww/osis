---- MODULE NetOpen ----
(* Who may open sync ID S on a connection (issues/sync-rewrite.md, the open rule): S is in a
   connection's shared set exactly while each side syncs S and holds proof, judged by itself on
   what it holds now, that the other may hold S: J (a proven actor holds sync or above), a secret
   credential shown on this connection (the sync-key proof), or an open signature by a credential
   key (sync key, a link key's static entry) of the newest step of S it knows, bound to the
   signer's side and this connection. Who dialed proves nothing. Opens are re-judged on every
   change a node learns (roster, head); an open on a basis no longer accepted ends, with a Lost
   that closes the other side too.
   Honest nodes: readers (hold the roster, every seed of a step they held, show the proof of their
   newest step and the static entries the roster lists; Hit a store's sync key, older steps too
   by their walk), stores (hold S unread: the head's seed only, show its sync key, its proof and
   the listed static entries; Hit a sync key or proof at their head), link holders (hold
   a link key whose static entry S lists, no seed; Hit their own static entry). Events (a fixed
   order, each at any time; each honest node learns them in order at its own pace): a grant, a
   removal (roster and static entries) and a rotation (a new step and seed, given to every member
   that learns it). Adv knows every event at once, holds every public value of S (each step's sync
   public key, every static entry), the seed and proof of every step it was an account member
   at, its link key if it has one; it picks its Hello challenges from those it has seen, dials
   and is dialed by anyone, Hits anything a peer ever showed it (a stored filter keeps removed
   entries), answers any Hit with any token it holds or makes, and replays any token it was sent.
   A token (a signature, or a Hit or tag keyed by a secret match value, always bound to its
   sender's side) is modelled by its key, side, the verifier's challenge and the listener's key.
   An answer to a Hit on a sync key or static entry is signed by the sync key of the replier's
   step (a store's head, a reader's newest known step), made only while it holds that seed.
   With AdvPublic FALSE, Adv holds no value of S at all; with AdvJunk its filter may show an entry
   matching anything an honest tester tests (a false positive), which the tester Hits. A tester
   ends with Lost only an acceptance that carries a valid tag (LostTag): one keyed by the Hit's
   match, which Adv can make only for a value it holds.
   A store granted later keeps S with no step until a reader registers its genesis there, which
   a reader does once S is open both ways and the store holds no step. With no head (ShownKey)
   it shows and tests the sync key and proof of the step its grant names, the newest it learned,
   so its own Hit opens S; a reader tests nothing again at a change of the store's filter.
   A rule of the design is a flag. *)
EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Nodes, Adv,
    Role,           \* Role[n] \in {"reader", "store", "link"} for n # Adv
    AdvLink,        \* Adv's role on S is by a link key (a static entry), else by its account
    InitMembers,    \* who holds sync on S at the start
    Events,         \* [op |-> "grant" | "rm" | "rot", n |-> node or "-"], in order
    MaxConn,
    SideByte,       \* an open signature's digest holds the signer's side (dialer 0, listener 1)
    AnswerSig,      \* a tester opens only on J or the replier's proof (answer signature or secret tag)
    ListenerSigns,  \* FALSE: a listener never makes an open signature (the rejected option)
    ProofSecret,    \* the proof derives from the seed, not from the public sync key
    NewestOnly,     \* a sync key counts only at the newest step the verifier knows
    ProofNewest,    \* a proof counts only at the newest step the verifier knows
    LinkNewest,     \* a static entry counts only if the newest roster the verifier knows lists it
    JNow,           \* J reads the roster the node holds now (FALSE: the roster it started with)
    Rejudge,        \* the bases ("J", "sync", "proof", "link") an open is re-judged on at a change
    Departed,       \* a credential of a peer J judges departed counts only at a step covering it
    DialProves,     \* TRUE: the dialer opens toward the key it dialed (who dialed proves nothing)
    AdvPublic,      \* Adv holds S's public values (each step's sync key, every static entry)
    AdvJunk,        \* Adv's filter may show junk matching any value a tester tests
    LostTag,        \* a Lost answers only an acceptance with a valid tag (FALSE: any acceptance)
    ShownKey        \* a store with no step shows and tests its grant's step's sync key and proof

Honest == Nodes \ {Adv}
NE == Len(Events)
IsRm(e, n) == e.op = "rm" /\ e.n = n

\* The roster and the step after the first k events.
Mem[k \in 0..NE] ==
    IF k = 0 THEN InitMembers
    ELSE IF Events[k].op = "grant" THEN Mem[k - 1] \cup {Events[k].n}
    ELSE IF Events[k].op = "rm" THEN Mem[k - 1] \ {Events[k].n}
    ELSE Mem[k - 1]
St[k \in 0..NE] == IF k = 0 THEN 0 ELSE St[k - 1] + (IF Events[k].op = "rot" THEN 1 ELSE 0)
LinkNodes == {n \in Honest : Role[n] = "link"} \cup (IF AdvLink THEN {Adv} ELSE {})
Account(k) == Mem[k] \ LinkNodes
Listed(k) == Mem[k] \cap LinkNodes
IsReader(n) == n \in Honest /\ Role[n] = "reader"
IsStore(n) == n \in Honest /\ Role[n] = "store"
\* p departed in the first k events (a removal of p, not granted again), and whether a rotation
\* after every removal covers it.
Gone(p, k) == p \notin Mem[k] /\ \E j \in 1..k : IsRm(Events[j], p)
Covers(k) == \E j \in 1..k : Events[j].op = "rot" /\ \A j2 \in 1..k : Events[j2].op = "rm" => j2 < j

\* Keys and tokens are records of one shape (TLC compares only like values).
Key(c, s, a) == [c |-> c, s |-> s, a |-> a]
SyncK(s) == Key("sync", s, "-")
ProofK(s) == Key("proof", s, "-")
LinkK(a) == Key("link", 0, a)
JB == Key("J", 0, "-")
DialB == Key("dial", 0, "-")
Secret(key) == key.c = "proof"
Tok(key, sd, ch, lk) == [k |-> key, sd |-> sd, ch |-> ch, lk |-> lk]
NoTok == Tok(Key("none", 0, "-"), 0, 0, "-")

VARIABLES conns, opens, known, seen, next, happened, know,
    leak,       \* a Lost named S to Adv while Adv held no value of S
    head        \* head[n]: a store holds a step of S (its genesis registered there)
vars == <<conns, opens, known, seen, next, happened, know, leak, head>>

KnowOf(n) == IF n = Adv THEN happened ELSE know[n]
\* The steps whose seed n holds (and so their sync key and proof).
Seeds(n) ==
    IF n = Adv THEN {St[j] : j \in {j \in 0..happened : Adv \in Account(j)}}
    ELSE IF Role[n] = "reader" THEN {St[j] : j \in {j \in 0..know[n] : n \in Mem[j]}}
    ELSE IF Role[n] = "store" /\ n \in Mem[know[n]] /\ (head[n] \/ ShownKey) THEN {St[know[n]]}
    ELSE {}
HoldsKeys(n) ==
    {SyncK(s) : s \in Seeds(n)} \cup {ProofK(s) : s \in Seeds(n)}
    \cup (IF n \in LinkNodes THEN {LinkK(n)} ELSE {})
    \cup (IF n = Adv /\ ~ProofSecret THEN {ProofK(s) : s \in 0..St[happened]} ELSE {})
Syncs(n) == n \in Mem[know[n]]
\* What honest n's filter shows when it knows k events; what a stored copy of it holds (nothing
\* is removed from a stored filter); what Adv shows.
ShowsAt(n, k) ==
    IF Role[n] = "store" /\ ~head[n] /\ ~ShownKey THEN {} ELSE
    (IF Role[n] = "store" THEN {SyncK(St[k]), ProofK(St[k])} ELSE IF Role[n] = "reader" THEN {ProofK(St[k])} ELSE {})
    \cup (IF Role[n] = "link" THEN {} ELSE {LinkK(a) : a \in Listed(k)})
ShowsEver(n) == UNION {ShowsAt(n, j) : j \in 0..know[n]}
PubValues == IF AdvPublic THEN {SyncK(s) : s \in 0..St[happened]} \cup {LinkK(a) : a \in LinkNodes} ELSE {}
\* the values of S Adv holds: it can make a tag keyed by any of them
AdvValues == PubValues \cup HoldsKeys(Adv)
AdvShows == PubValues \cup {key \in HoldsKeys(Adv) : key.c = "proof"}
\* What honest t Hits in a peer's filter: a reader a sync key it holds (its walk: older steps
\* too); a store its head's sync key or proof; a link holder its own static entry.
Tests(t, v) ==
    CASE Role[t] = "reader" -> v.c = "sync" /\ v \in HoldsKeys(t)
      [] Role[t] = "store" -> v.c \in {"sync", "proof"} /\ v.s = St[know[t]] /\ v \in HoldsKeys(t)
      [] OTHER -> v = LinkK(t)

\* J: a reader judges a proven actor by the roster it holds.
J(v, p, k) == IsReader(v) /\ p \in Account(IF JNow THEN k ELSE 0)
\* v, knowing k events, accepts key shown by peer p (a Hit on its filter or an answer to its Hit).
Accept(v, k, key, p) ==
    /\ CASE key.c = "sync" -> IF NewestOnly THEN key.s = St[k] ELSE key.s <= St[k]
         [] key.c = "proof" -> (IF ProofNewest THEN key.s = St[k] ELSE key.s <= St[k])
                               /\ key.s \in {St[j] : j \in {j \in 0..k : v \in Mem[j]}}
         [] key.c = "link" -> key.a \in (IF LinkNewest THEN Listed(k) ELSE UNION {Listed(j) : j \in 0..k})
         [] OTHER -> FALSE
    /\ (Departed /\ IsReader(v) /\ Gone(p, k)) => Covers(k)

Side(c, n) == IF n = c.d THEN 0 ELSE 1
Peer(c, n) == IF n = c.d THEN c.l ELSE c.d
Ch(c, n) == IF n = c.d THEN c.cd ELSE c.cl
CanSign(n, c, key) == ListenerSigns \/ Secret(key) \/ n = c.d
\* Token s, verified by n on c as made by the other side with key.
Valid(s, key, c, n) ==
    /\ s.k = key
    /\ (SideByte \/ Secret(key)) => s.sd = Side(c, Peer(c, n))
    /\ s.ch = Ch(c, n)
    /\ s.lk = c.l
    /\ CanSign(Peer(c, n), c, key)
\* The tokens Adv makes on c for verifier n.
Forge(c, n) == {Tok(key, Side(c, Adv), Ch(c, n), c.l) : key \in HoldsKeys(Adv)}
IsOpen(i, n) == \E o \in opens : o[1] = i /\ o[2] = n

\* Tester t's open toward p on the answer a to its Hit on v: on J, else on the answer, a proof
\* t accepts of the class the Hit asks (the tag on a proof, else an open signature by a sync
\* key); else Lost, closing both sides.
Finish(i, t, p, v, a, base) ==
    LET c == conns[i]
        \* the peer accepted (an honest one always, with a valid tag); Adv answering with any token
        \* accepted, its tag valid only on a match it holds
        accepted == p # Adv \/ a # NoTok
        tagOK == p # Adv \/ v \in AdvValues
        lost == accepted /\ (LostTag => tagOK)
        opensT == IF J(t, p, know[t]) \/ ~AnswerSig THEN TRUE
                  ELSE /\ a # NoTok /\ Valid(a, a.k, c, t)
                       /\ a.k.c = (IF v.c = "proof" THEN "proof" ELSE "sync")
                       /\ Accept(t, know[t], a.k, p)
    IN
    /\ leak' = (leak \/ (p = Adv /\ ~opensT /\ lost /\ AdvValues = {}))
    /\ opens' = IF ~AnswerSig THEN base \cup {<<i, t, v>>}
             ELSE IF J(t, p, know[t]) THEN base \cup {<<i, t, JB>>}
             ELSE IF /\ a # NoTok /\ Valid(a, a.k, c, t)
                     /\ a.k.c = (IF v.c = "proof" THEN "proof" ELSE "sync")
                     /\ Accept(t, know[t], a.k, p)
                  THEN base \cup {<<i, t, a.k>>}
             ELSE IF lost THEN {o \in base : o[1] # i}
             ELSE base

Init ==
    /\ conns = <<>>
    /\ opens = {}
    /\ known = {}
    /\ seen = {}
    /\ next = 1
    /\ happened = 0
    /\ know = [n \in Honest |-> 0]
    /\ leak = FALSE
    /\ head = [n \in Honest |-> Role[n] # "store" \/ n \in InitMembers]

\* A connection: honest sides draw a fresh challenge; Adv any it has seen, the other side's of
\* this connection, or a fresh one.
Connect(d, l) ==
    /\ Len(conns) < MaxConn
    /\ d # l
    /\ \E cd \in (IF d = Adv THEN seen \cup {next, next + 1} ELSE {next}),
          cl \in (IF l = Adv THEN seen \cup {next, next + 1} ELSE {next + 1}) :
        /\ conns' = Append(conns, [d |-> d, l |-> l, cd |-> cd, cl |-> cl])
        /\ seen' = IF Adv \in {d, l} THEN seen \cup {cd, cl} ELSE seen
    /\ next' = next + 2
    /\ UNCHANGED <<opens, known, happened, know, leak, head>>

Happen ==
    /\ happened < NE
    /\ happened' = happened + 1
    /\ UNCHANGED <<conns, opens, known, seen, next, know, leak, head>>

\* Honest n learns the next event and re-judges every open it holds on what it holds now; an open
\* whose basis it no longer accepts ends (with its Lost, both sides). A node that stops syncing S
\* ends them all.
Learn(n) ==
    LET k == know[n] + 1
        Keep(o) == LET p == Peer(conns[o[1]], n) b == o[3] IN
            /\ n \in Mem[k]
            /\ CASE b.c = "J" -> "J" \notin Rejudge \/ J(n, p, k)
                 [] b.c \in {"sync", "proof", "link"} -> b.c \notin Rejudge \/ Accept(n, k, b, p)
                 [] OTHER -> TRUE
        Drop == {o[1] : o \in {o \in opens : o[2] = n /\ ~Keep(o)}}
    IN
    /\ know[n] < happened
    /\ know' = [know EXCEPT ![n] = k]
    /\ opens' = {o \in opens : o[1] \notin Drop}
    /\ UNCHANGED <<conns, known, seen, next, happened, leak, head>>

\* Honest t Hits v in its peer's filter with a token made over its own side, the peer's challenge
\* and the listener's key. An honest peer opens if it accepts v and answers with its proof: the tag
\* on a proof, else its open signature by the sync key of the step the open is at. Adv collects
\* the token and answers with any token it holds or makes.
HonestHit(i, t, v) ==
    LET c == conns[i]
        p == Peer(c, t)
        s == Tok(v, Side(c, t), Ch(c, p), c.l)
    IN
    /\ t \in Honest /\ t \in {c.d, c.l}
    /\ ~IsOpen(i, t)
    /\ Syncs(t) /\ Tests(t, v) /\ CanSign(t, c, v)
    /\ IF p = Adv
       THEN /\ v \in AdvShows \/ AdvJunk
            /\ known' = IF v \in HoldsKeys(Adv) THEN known ELSE known \cup {s}
            /\ \E a \in known' \cup Forge(c, t) \cup {NoTok} : Finish(i, t, p, v, a, opens)
       ELSE LET ak == IF v.c = "proof" THEN v
                      ELSE SyncK(IF v.c = "sync" THEN v.s ELSE St[know[p]])
                a == IF ak \in HoldsKeys(p) /\ CanSign(p, c, ak)
                     THEN Tok(ak, Side(c, p), Ch(c, t), c.l) ELSE NoTok
            IN /\ v \in ShowsAt(p, know[p])
               /\ Syncs(p) /\ Accept(p, know[p], v, t)
               /\ Finish(i, t, p, v, a, IF IsOpen(i, p) THEN opens ELSE opens \cup {<<i, p, v>>})
               /\ UNCHANGED known
    /\ UNCHANGED <<conns, seen, next, happened, know, head>>

\* Adv Hits v, anything h ever showed it, with any token it holds or makes; h opens toward Adv when
\* it accepts, and answers with its proof, which Adv keeps.
AdvHit(i, v) ==
    LET c == conns[i]
        h == Peer(c, Adv)
        ak == IF v.c = "proof" THEN v ELSE SyncK(IF v.c = "sync" THEN v.s ELSE St[know[h]])
    IN
    /\ Adv \in {c.d, c.l}
    /\ ~IsOpen(i, h)
    /\ v \in ShowsEver(h)
    /\ Syncs(h) /\ Accept(h, know[h], v, Adv)
    /\ \E s \in known \cup Forge(c, h) : Valid(s, v, c, h)
    /\ opens' = opens \cup {<<i, h, v>>}
    /\ known' = IF ak \in HoldsKeys(h) /\ CanSign(h, c, ak) /\ ak \notin HoldsKeys(Adv)
                THEN known \cup {Tok(ak, Side(c, h), Ch(c, Adv), c.l)} ELSE known
    /\ UNCHANGED <<conns, seen, next, happened, know, leak, head>>

\* A reader opens toward a peer J judges a holder (ByRole); Adv proves its account to anyone.
JOpen(i, v) ==
    LET c == conns[i] IN
    /\ v \in {c.d, c.l} /\ ~IsOpen(i, v)
    /\ Syncs(v) /\ J(v, Peer(c, v), know[v])
    /\ opens' = opens \cup {<<i, v, JB>>}
    /\ UNCHANGED <<conns, known, seen, next, happened, know, leak, head>>

\* The rejected rule: a dialer opens toward the key it dialed.
DialOpen(i) ==
    LET c == conns[i] IN
    /\ DialProves /\ c.d \in Honest /\ ~IsOpen(i, c.d) /\ Syncs(c.d)
    /\ opens' = opens \cup {<<i, c.d, DialB>>}
    /\ UNCHANGED <<conns, known, seen, next, happened, know, leak, head>>

\* Reader r, S open both ways on connection i toward a store p holding no step (spec/sync-ids.md
\* §6 Walk, Moving it): r registers its genesis there.
Register(i, r) ==
    LET p == Peer(conns[i], r) IN
    /\ IsReader(r) /\ IsStore(p) /\ ~head[p]
    /\ IsOpen(i, r) /\ IsOpen(i, p)
    /\ head' = [head EXCEPT ![p] = TRUE]
    /\ UNCHANGED <<conns, opens, known, seen, next, happened, know, leak>>

Values == {SyncK(s) : s \in 0..St[NE]} \cup {ProofK(s) : s \in 0..St[NE]} \cup {LinkK(a) : a \in LinkNodes}

HonestNext ==
    \/ \E n \in Honest : Learn(n)
    \/ \E i \in 1..Len(conns), t \in Honest, v \in Values : HonestHit(i, t, v)
    \/ \E i \in 1..Len(conns), v \in Honest : JOpen(i, v)
    \/ \E i \in 1..Len(conns) : DialOpen(i)
    \/ \E i \in 1..Len(conns), r \in Honest : Register(i, r)

Next ==
    \/ HonestNext
    \/ \E d, l \in Nodes : Connect(d, l)
    \/ Happen
    \/ \E i \in 1..Len(conns), v \in Values : AdvHit(i, v)

Spec == Init /\ [][Next]_vars /\ WF_vars(HonestNext)

\* No honest node opens S toward Adv unless Adv holds sync on S in the roster it knows, or holds
\* the seed of the newest step it knows (removed, the rotation not yet known). Adv holding only
\* public values of S, it never opens.
Safe == \A o \in opens :
    LET n == o[2] IN
    (n \in Honest /\ Peer(conns[o[1]], n) = Adv) =>
        (Adv \in Mem[know[n]] \/ St[know[n]] \in Seeds(Adv))

\* Adv holding no value of S learns nothing of S from a Lost: no Lost names S to it.
Private == ~leak

\* A removal ends at once: no reader opens toward Adv once it knows Adv's removal.
SafeRm == \A o \in opens :
    LET n == o[2] IN
    (IsReader(n) /\ Peer(conns[o[1]], n) = Adv) => ~Gone(Adv, know[n])

\* Two honest holders connected, every event known to all, end up open both ways, whichever dialed.
Stable == happened = NE /\ \A n \in Honest : know[n] = NE
HonestPair(i) == i <= Len(conns) /\ {conns[i].d, conns[i].l} \subseteq Honest \cap Mem[NE]
Live == \A i \in 1..MaxConn :
    (HonestPair(i) /\ Stable) ~> (i <= Len(conns) /\ IsOpen(i, conns[i].d) /\ IsOpen(i, conns[i].l))
====
