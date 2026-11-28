---- MODULE NetOpen ----
(* Who may open sync ID S on a connection (spec/sync-opens.md §4, the one open rule): S is in a
   connection's shared set exactly while each side syncs S and holds, judged by itself on what it
   holds now, a credential of S the other showed on this connection: the sync proof of a step's
   sync key on its path, or a claim key among its head claim keys proven by an open signature bound to the
   signer's side and this connection. A credential of the head opens S whole; an older step's sync
   proof opens S served up to that step's end. Nothing else opens S: which side dialed, a deposit
   key (public), a claim key bound to an older epoch.
   Steps are a chain (step = sync epoch); events in a fixed order, each at any time, each honest
   node learning them in order at its own pace: a grant (a claim bound to the current epoch, no
   new step), a removal (it rotates: a new step whose seed and claims reach every other holder),
   a rotation. Removal ends opens by the head move alone: at a head move a node ends each whole
   open whose credential is of an older step, served up to that step's end (`until`); an ended
   open closes (its Lost) at any time after.
   Honest nodes are readers or stores (the class only: both hold the seeds of the steps they were
   holders at once they took their claims, show the sync proof of each step on their path whose
   seed they hold, their head claim keys (every holder's claim key at the head) and the head's deposit key,
   and test their held seeds' proofs newest first and, while no held seed derives the source's
   step's key, their own claim key at the source's head). A holder granted later takes its claims
   (its seeds) only once it is open whole toward an honest peer (pulling S; the store's head
   registered by that peer, abstracted): before, it shows and accepts nothing and opens by its
   claim key alone.
   Adv knows every event at once. It holds the seed and proof of every step it was a holder at,
   its claim key at every step it knows (a claim key derives from the public step key and its own key)
   and, with AdvPublic, every public value of S (each step and deposit key, every claim key
   in S's clear claim blocks). It picks its Hello challenges from those it has seen or the other
   side's fresh one, dials and is dialed by anyone, answers Head with any step, Hits anything a
   peer ever showed it (a stored filter keeps removed entries), answers any Hit with any token it
   holds or makes, and replays any token it was sent. A token (a Hit keyed by a proof, an open
   signature by a claim key, a tag keyed by a proof, an answer signature by a sync key) is
   modelled by its key, its signer's side, the verifier's challenge and the listener's key.
   With AdvPublic FALSE, Adv holds no value of S; with AdvJunk its filter may show an entry
   matching anything an honest tester tests (a false positive), which the tester Hits. A tester
   ends with Lost only an acceptance whose answer is valid (LostTag).
   Each open records the class of its peer as the peer declared it (Declared).
   A rule of the design is a flag. *)
EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Nodes, Adv,
    Role,           \* Role[n] \in {"reader", "store"} for n # Adv: the class it declares
    InitMembers,    \* the holders at the start (holding their claims)
    Events,         \* [op |-> "grant" | "rm" | "rot", n |-> node or "-"], in order
    MaxConn,
    SideByte,       \* a claim key's open signature (and an answer signature) holds the signer's side
    AnswerSig,      \* a tester opens only on a valid answer (FALSE: on its own credential alone)
    ProofSecret,    \* the proof derives from the seed, not from the public sync key
    OlderEnds,      \* an older step's proof opens S served up to that step's end (FALSE: whole)
    HeadEnds,       \* a head move ends each whole open by an older step's credential
    ClaimOld,       \* TRUE: a claim key bound to an older epoch counts (the rejected rule)
    DepositOpens,   \* TRUE: a Hit on the head's deposit key opens (the rejected rule)
    Claims,         \* a holder holding no seed of the source's step tests its claim key there
    DialProves,     \* TRUE: the dialer opens toward the key it dialed (who dialed proves nothing)
    AdvPublic,      \* Adv holds S's public values
    AdvJunk,        \* Adv's filter may show junk matching any value a tester tests
    LostTag,        \* a Lost answers only an acceptance with a valid answer (FALSE: any acceptance)
    Declared        \* an open's class of its peer is the peer's declaration (FALSE: from the credential)

Honest == Nodes \ {Adv}
NE == Len(Events)

\* The holders and the step after the first k events.
Mem[k \in 0..NE] ==
    IF k = 0 THEN InitMembers
    ELSE IF Events[k].op = "grant" THEN Mem[k - 1] \cup {Events[k].n}
    ELSE IF Events[k].op = "rm" THEN Mem[k - 1] \ {Events[k].n}
    ELSE Mem[k - 1]
St[k \in 0..NE] == IF k = 0 THEN 0 ELSE St[k - 1] + (IF Events[k].op \in {"rm", "rot"} THEN 1 ELSE 0)
\* The holders boxed at step s by the first k events (each with a claim bound to s).
HoldersAt(s, k) == {a \in Nodes : \E j \in 0..k : St[j] = s /\ a \in Mem[j]}

\* Keys and tokens are records of one shape (TLC compares only like values).
Key(c, s, a) == [c |-> c, s |-> s, a |-> a]
SyncK(s) == Key("sync", s, "-")
ProofK(s) == Key("proof", s, "-")
ClaimK(a, s) == Key("claim", s, a)
DepK(s) == Key("dep", s, "-")
DialB == Key("dial", 0, "-")
Tok(key, sd, ch, lk) == [k |-> key, sd |-> sd, ch |-> ch, lk |-> lk]
NoTok == Tok(Key("none", 0, "-"), 0, 0, "-")
\* The key an answer to a Hit on v carries: the tag keyed by the proof, else a signature by the
\* sync key of the replier's head (the claim key's step).
AnsKey(v) == IF v.c = "proof" THEN v ELSE SyncK(v.s)
\* What n declares of itself; Adv declares what it likes ("adv").
Cls(n) == IF n = Adv THEN "adv" ELSE Role[n]
\* The rejected rule: the class from the credential that opened S.
ClassOf(p, v) == IF Declared THEN Cls(p) ELSE IF v.c = "proof" THEN "store" ELSE "reader"
\* An open: connection, node, mode ("whole" or "until"), the credential's step, until, class.
Open(i, n, m, s, cl) == [i |-> i, n |-> n, m |-> m, s |-> s, u |-> s, cl |-> cl]

VARIABLES conns, opens, known, seen, next, happened, know,
    leak,       \* a Lost named S to Adv while Adv held no value of S
    took        \* took[n]: n holds its claims (its seeds and S's claim blocks)
vars == <<conns, opens, known, seen, next, happened, know, leak, took>>

HeadOf(n) == IF n = Adv THEN St[happened] ELSE St[know[n]]
\* The steps whose seed n holds.
Seeds(n) ==
    IF n = Adv THEN {St[j] : j \in {j \in 0..happened : Adv \in Mem[j]}}
    ELSE IF took[n] THEN {St[j] : j \in {j \in 0..know[n] : n \in Mem[j]}}
    ELSE {}
\* The steps Adv knows the public step key of.
AdvSteps == IF AdvPublic THEN 0..St[happened] ELSE Seeds(Adv)
HoldsKeys(n) ==
    {SyncK(s) : s \in Seeds(n)} \cup {ProofK(s) : s \in Seeds(n)}
    \cup {ClaimK(n, s) : s \in (IF n = Adv THEN AdvSteps ELSE 0..HeadOf(n))}
    \cup (IF n = Adv /\ AdvPublic /\ ~ProofSecret THEN {ProofK(s) : s \in 0..St[happened]} ELSE {})
    \cup (IF n = Adv /\ AdvPublic THEN {DepK(s) : s \in 0..St[happened]} ELSE {})
Syncs(n) == n \in Mem[know[n]]
HeadClaims(n, k) == {ClaimK(a, St[k]) : a \in HoldersAt(St[k], k)}
\* What honest n's filter shows knowing k events.
ShowsAt(n, k) ==
    IF ~took[n] THEN {}
    ELSE {ProofK(s) : s \in {St[j] : j \in {j \in 0..k : n \in Mem[j]}}} \cup HeadClaims(n, k) \cup {DepK(St[k])}
ShowsEver(n) == UNION {ShowsAt(n, j) : j \in 0..know[n]}
PubValues ==
    IF AdvPublic THEN {DepK(s) : s \in 0..St[happened]} \cup {ClaimK(a, s) : a \in Nodes, s \in 0..St[happened]}
    ELSE {}
\* the values of S Adv holds
AdvValues == PubValues \cup HoldsKeys(Adv)
AdvShows == PubValues \cup {key \in HoldsKeys(Adv) : key.c \in {"proof", "claim"}}

\* How v, knowing k events, takes credential key shown by its peer: "whole", "until" (an older
\* step's proof: served up to that step's end) or "no".
Accept(v, k, key) ==
    IF ~took[v] THEN "no"
    ELSE CASE key.c = "proof" /\ key.s \in Seeds(v) ->
                IF key.s = St[k] \/ ~OlderEnds THEN "whole" ELSE "until"
           [] key.c = "claim" /\ (IF ClaimOld THEN key.s <= St[k] ELSE key.s = St[k])
                /\ key.a \in HoldersAt(key.s, k) -> "whole"
           [] key.c = "dep" /\ DepositOpens /\ key.s = St[k] -> "whole"
           [] OTHER -> "no"
\* How tester t takes its own credential v once the peer's answer proves it: a proof by where its
\* step lies on t's path; a claim key at t's head whole, at an older step of t's up to its end, at a
\* step t holds no claim block of not at all.
TesterMode(t, v) ==
    CASE v.c = "proof" -> IF v.s = HeadOf(t) \/ ~OlderEnds THEN "whole" ELSE "until"
      [] v.c = "claim" /\ t \in HoldersAt(v.s, know[t]) -> IF v.s = HeadOf(t) THEN "whole" ELSE "until"
      [] OTHER -> "no"
\* What honest t tests toward peer p, whose head it learned (Adv answers Head with any step).
Tests(t, p, v) ==
    \/ v.c = "proof" /\ v.s \in Seeds(t)
       /\ (p # Adv => \A s \in Seeds(t) : ProofK(s) \in ShowsAt(p, know[p]) => s <= v.s)
    \/ v.c = "claim" /\ Claims /\ v.a = t
       /\ v.s \in (IF p = Adv THEN 0..St[happened] ELSE {HeadOf(p)})
       /\ v.s \notin Seeds(t)

Side(c, n) == IF n = c.d THEN 0 ELSE 1
Peer(c, n) == IF n = c.d THEN c.l ELSE c.d
Ch(c, n) == IF n = c.d THEN c.cd ELSE c.cl
\* Token s, verified by n on c as made by the other side with key.
Valid(s, key, c, n) ==
    /\ s.k = key
    /\ (SideByte \/ key.c = "proof") => s.sd = Side(c, Peer(c, n))
    /\ s.ch = Ch(c, n)
    /\ s.lk = c.l
\* The tokens Adv makes on c for verifier n.
Forge(c, n) == {Tok(key, Side(c, Adv), Ch(c, n), c.l) : key \in HoldsKeys(Adv)}
IsOpen(i, n) == \E o \in opens : o.i = i /\ o.n = n
Served(o) == IF o.m = "whole" THEN HeadOf(o.n) ELSE o.u

\* Tester t's open toward p on the answer a to its Hit on v; else, the peer having accepted, Lost
\* closing both sides.
Finish(i, t, p, v, a, base) ==
    LET c == conns[i]
        accepted == p # Adv \/ a # NoTok
        answerOK == a # NoTok /\ Valid(a, AnsKey(v), c, t)
        mode == IF ~AnswerSig \/ answerOK THEN TesterMode(t, v) ELSE "no"
        lost == accepted /\ mode = "no" /\ (LostTag => answerOK)
    IN
    /\ leak' = (leak \/ (p = Adv /\ lost /\ AdvValues = {}))
    /\ opens' = IF mode # "no" THEN base \cup {Open(i, t, mode, v.s, ClassOf(p, v))}
                ELSE IF lost THEN {o \in base : o.i # i}
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
    /\ took = [n \in Honest |-> n \in InitMembers]

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
    /\ UNCHANGED <<opens, known, happened, know, leak, took>>

Happen ==
    /\ happened < NE
    /\ happened' = happened + 1
    /\ UNCHANGED <<conns, opens, known, seen, next, know, leak, took>>

\* Honest n learns the next event. At a head move each whole open of n by an older step's
\* credential is ended, served up to that step's end.
Learn(n) ==
    LET k == know[n] + 1
        End(o) == IF HeadEnds /\ o.n = n /\ o.m = "whole" /\ o.s < St[k] THEN [o EXCEPT !.m = "until"] ELSE o
    IN
    /\ know[n] < happened
    /\ know' = [know EXCEPT ![n] = k]
    /\ opens' = {End(o) : o \in opens}
    /\ UNCHANGED <<conns, known, seen, next, happened, leak, took>>

\* An ended open closes (its Lost, past `until`): both sides of the connection's S.
Close(i, n) ==
    /\ \E o \in opens : o.i = i /\ o.n = n /\ o.m = "until"
    /\ opens' = {o \in opens : o.i # i}
    /\ UNCHANGED <<conns, known, seen, next, happened, know, leak, took>>

\* Honest t Hits v with a token over its own side, the peer's challenge and the listener's key. An
\* honest peer opens if it takes v and answers (the tag keyed by a proof, else its signature by its
\* head's sync key). Adv collects the token and answers with any token it holds or makes.
HonestHit(i, t, v) ==
    LET c == conns[i]
        p == Peer(c, t)
        s == Tok(v, Side(c, t), Ch(c, p), c.l)
    IN
    /\ t \in {c.d, c.l}
    /\ ~IsOpen(i, t)
    /\ Syncs(t) /\ Tests(t, p, v)
    /\ IF p = Adv
       THEN /\ v \in AdvShows \/ AdvJunk
            \* (a token keyed by a key Adv holds adds nothing: it makes its own)
            /\ known' = IF v \in HoldsKeys(Adv) THEN known ELSE known \cup {s}
            /\ \E a \in known' \cup Forge(c, t) \cup {NoTok} : Finish(i, t, p, v, a, opens)
       ELSE LET mp == Accept(p, know[p], v)
                a == IF AnsKey(v) \in HoldsKeys(p) THEN Tok(AnsKey(v), Side(c, p), Ch(c, t), c.l) ELSE NoTok
            IN /\ v \in ShowsAt(p, know[p])
               /\ Syncs(p) /\ mp # "no"
               /\ Finish(i, t, p, v, a, IF IsOpen(i, p) THEN opens ELSE opens \cup {Open(i, p, mp, v.s, ClassOf(t, v))})
               /\ UNCHANGED known
    /\ UNCHANGED <<conns, seen, next, happened, know, took>>

\* Adv Hits v, anything h ever showed it, with any token it holds or makes; h opens toward Adv when
\* it takes v, and answers, which Adv keeps.
AdvHit(i, v) ==
    LET c == conns[i]
        h == Peer(c, Adv)
        mh == Accept(h, know[h], v)
    IN
    /\ Adv \in {c.d, c.l}
    /\ ~IsOpen(i, h)
    /\ v \in ShowsEver(h)
    /\ Syncs(h) /\ mh # "no"
    /\ \E s \in known \cup Forge(c, h) : Valid(s, v, c, h)
    /\ opens' = opens \cup {Open(i, h, mh, v.s, ClassOf(Adv, v))}
    /\ known' = IF AnsKey(v) \in HoldsKeys(h) /\ AnsKey(v) \notin HoldsKeys(Adv) THEN known \cup {Tok(AnsKey(v), Side(c, h), Ch(c, Adv), c.l)} ELSE known
    /\ UNCHANGED <<conns, seen, next, happened, know, leak, took>>

\* The rejected rule: a dialer opens toward the key it dialed.
DialOpen(i) ==
    LET c == conns[i] IN
    /\ DialProves /\ c.d \in Honest /\ ~IsOpen(i, c.d) /\ Syncs(c.d)
    /\ opens' = opens \cup {Open(i, c.d, "whole", 0, "reader")}
    /\ UNCHANGED <<conns, known, seen, next, happened, know, leak, took>>

\* A holder granted later, open whole toward an honest peer, pulls S and takes its claims.
Take(n) ==
    /\ ~took[n] /\ Syncs(n)
    /\ \E o \in opens : o.n = n /\ o.m = "whole" /\ Peer(conns[o.i], n) # Adv
    /\ took' = [took EXCEPT ![n] = TRUE]
    /\ UNCHANGED <<conns, opens, known, seen, next, happened, know, leak>>

Values ==
    {ProofK(s) : s \in 0..St[NE]} \cup {DepK(s) : s \in 0..St[NE]}
    \cup {ClaimK(a, s) : a \in Nodes, s \in 0..St[NE]}

HonestNext ==
    \/ \E n \in Honest : Learn(n) \/ Take(n)
    \/ \E i \in 1..Len(conns), t \in Honest, v \in Values : HonestHit(i, t, v)
    \/ \E i \in 1..Len(conns), n \in Honest : Close(i, n)
    \/ \E i \in 1..Len(conns) : DialOpen(i)

Next ==
    \/ HonestNext
    \/ \E d, l \in Nodes : Connect(d, l)
    \/ Happen
    \/ \E i \in 1..Len(conns), v \in Values : AdvHit(i, v)

\* Honest steps on one connection; each connection progresses on its own (weak fairness per
\* connection, so a loop with Adv on one starves no other).
HonestOn(i) == i <= Len(conns) /\ \/ \E t \in Honest, v \in Values : HonestHit(i, t, v)
                                  \/ \E n \in Honest : Close(i, n)
Fairness == /\ \A n \in Honest : WF_vars(Learn(n)) /\ WF_vars(Take(n))
            /\ \A i \in 1..MaxConn : WF_vars(HonestOn(i))
Spec == Init /\ [][Next]_vars /\ Fairness

\* No honest node serves Adv a step Adv was not a holder at: a whole open serves the node's head,
\* an ended one up to its `until`. So a removed holder is served nothing past its removal's step
\* once the node knows the removal, and a node holding only S's public values is served nothing.
Entitled(s) == \E j \in 0..NE : St[j] = s /\ Adv \in Mem[j]
Safe == \A o \in opens :
    (o.n \in Honest /\ Peer(conns[o.i], o.n) = Adv) => Entitled(Served(o))

\* Adv holding no value of S learns nothing of S from a Lost: no Lost names S to it.
Private == ~leak

\* An open between honest nodes records the class its peer declared, whichever side's Hit opened
\* it and on whichever credential.
ClassRight == \A o \in opens :
    LET p == Peer(conns[o.i], o.n) IN
    (o.n \in Honest /\ p \in Honest) => o.cl = Cls(p)

\* Two honest holders connected, every event known to both, end up open whole both ways, whichever
\* dialed.
Stable == happened = NE /\ \A n \in Honest : know[n] = NE
HonestPair(i) == i <= Len(conns) /\ {conns[i].d, conns[i].l} \subseteq Honest \cap Mem[NE]
WholeOpen(i, n) == \E o \in opens : o.i = i /\ o.n = n /\ o.m = "whole"
Live == \A i \in 1..MaxConn :
    (HonestPair(i) /\ Stable) ~> (i <= Len(conns) /\ WholeOpen(i, conns[i].d) /\ WholeOpen(i, conns[i].l))
====
