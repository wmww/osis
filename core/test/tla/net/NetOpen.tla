---- MODULE NetOpen ----
(* Who may open sync ID L on a connection (issues/net-6c-plan.md): the 6c rule that each side
   opens L only on its own proof that the peer may hold L, and the open signature's domain.
   Honest nodes are readers (hold L's sync key and a key actor whose static entry L's head
   lists) or stores (hold L sync-only: its sync key); Adv holds every public value of L (sync
   and claim public keys, static entries, claim sets) and no secret of L's head. Adv picks its
   Hello challenges from those it has seen, dials anyone and is dialed by anyone, shows every
   public credential in its filter, answers any Hit with a tag (public match values) and replays
   any signature it was sent, on any connection. A rule of the design is a flag. *)
EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Nodes, Adv, Role,       \* Role[n] \in {"reader", "store"} for n # Adv
    MaxConn,
    SideByte,               \* the open signature's digest holds the signer's side (dialer 0, listener 1)
    AnswerSig,              \* a tester opens on a public-value Hit only on J or the replier's answer signature
    ListenerSigns           \* FALSE: a listener never makes an open signature (the rejected option)

Honest == Nodes \ {Adv}
None == [k |-> "none"]

\* Credential classes: SYNC (a store's head sync key), PROOF (the proof of it a reader shows),
\* STATIC (a key actor's static entry, signed as a Static item by the key actor). All are public
\* match values: a tag on them proves nothing.
KeyOf(cls) == IF cls = "STATIC" THEN "ka" ELSE "sync"
Holds(n) == IF n = Adv THEN {} ELSE IF Role[n] = "reader" THEN {"sync", "ka"} ELSE {"sync"}
\* What a filter shows (to every connection: the worst case for read credentials too).
Shows(n) == IF n = Adv THEN {"SYNC", "PROOF", "STATIC"}
            ELSE IF Role[n] = "store" THEN {"SYNC", "STATIC"} ELSE {"PROOF", "STATIC"}
\* What a node tests against a peer's filter: a reader its sync key at stores and its key actor's
\* entry anywhere; a store its sync key and its proof.
Tests(n) == IF Role[n] = "reader" THEN {"SYNC", "STATIC"} ELSE {"SYNC", "PROOF"}
\* J: a reader judges a peer by the rosters it holds (J counts sync: a store's account holds
\* sync on L); a store holds no roster. Adv's actors hold no role on L.
J(t, r) == Role[t] = "reader" /\ r # Adv

VARIABLES conns, served, known, seen, next
vars == <<conns, served, known, seen, next>>

Side(c, n) == IF n = c.d THEN 0 ELSE 1
Peer(c, n) == IF n = c.d THEN c.l ELSE c.d
Ch(c, n) == IF n = c.d THEN c.cd ELSE c.cl
Sig(k, sd, ch, lk) == [k |-> k, sd |-> sd, ch |-> ch, lk |-> lk]
\* An honest node signs only where the rule lets it.
CanSign(n, c) == ListenerSigns \/ n = c.d
\* Verified by n on c as made by the other side with key k.
Valid(s, k, c, n) ==
    /\ s.k = k
    /\ SideByte => s.sd = Side(c, Peer(c, n))
    /\ s.ch = Ch(c, n)
    /\ s.lk = c.l
    /\ ListenerSigns \/ Peer(c, n) = c.d

Init ==
    /\ conns = <<>>
    /\ served = {}
    /\ known = {}
    /\ seen = {}
    /\ next = 1

\* A connection: honest sides draw a fresh challenge; Adv any it has seen, or a fresh one.
Connect(d, l) ==
    /\ Len(conns) < MaxConn
    /\ d # l
    /\ \E cd \in (IF d = Adv THEN seen \cup {next} ELSE {next}),
          cl \in (IF l = Adv THEN seen \cup {next + 1} ELSE {next + 1}) :
        /\ conns' = Append(conns, [d |-> d, l |-> l, cd |-> cd, cl |-> cl])
        /\ seen' = IF Adv \in {d, l} THEN seen \cup {cd, cl} ELSE seen
    /\ next' = next + 2
    /\ UNCHANGED <<served, known>>

\* Honest t on connection i Hits a credential the peer's filter shows, signed over its own side,
\* the peer's challenge and the listener's key. An honest peer verifies it, opens (serves t) and
\* answers with its own signature by the sync key where it holds it; t opens on J or that.
\* Adv collects the signature and answers with a tag and any signature it holds.
HonestHit(i, t, cls) ==
    LET c == conns[i]
        p == Peer(c, t)
        s == Sig(KeyOf(cls), Side(c, t), Ch(c, p), c.l)
    IN
    /\ t \in Honest /\ t \in {c.d, c.l}
    /\ <<i, t>> \notin served
    /\ cls \in Tests(t) /\ cls \in Shows(p) /\ KeyOf(cls) \in Holds(t)
    /\ CanSign(t, c)
    /\ IF p = Adv
       THEN /\ known' = known \cup {s}
            /\ \E a \in known' \cup {None} :
                 served' = IF ~AnswerSig \/ (a # None /\ Valid(a, "sync", c, t))
                           THEN served \cup {<<i, t>>} ELSE served
       ELSE LET a == IF "sync" \in Holds(p) /\ CanSign(p, c)
                     THEN Sig("sync", Side(c, p), Ch(c, t), c.l) ELSE None
                tOpens == ~AnswerSig \/ J(t, p) \/ (a # None /\ Valid(a, "sync", c, t))
            IN /\ served' = served \cup {<<i, p>>} \cup (IF tOpens THEN {<<i, t>>} ELSE {})
               /\ UNCHANGED known
    /\ UNCHANGED <<conns, seen, next>>

\* Adv Hits honest h with any signature it holds, on a credential h's filter shows; h opens L
\* toward Adv when it verifies, and answers with its own signature (which Adv keeps).
AdvHit(i, cls) ==
    LET c == conns[i]
        h == Peer(c, Adv)
    IN
    /\ Adv \in {c.d, c.l}
    /\ cls \in Shows(h)
    /\ \E s \in known :
        /\ Valid(s, KeyOf(cls), c, h)
        /\ served' = served \cup {<<i, h>>}
        /\ known' = IF "sync" \in Holds(h) /\ CanSign(h, c)
                    THEN known \cup {Sig("sync", Side(c, h), Ch(c, Adv), c.l)} ELSE known
    /\ UNCHANGED <<conns, seen, next>>

Next ==
    \/ \E d, l \in Nodes : Connect(d, l)
    \/ \E i \in 1..Len(conns), t \in Honest, cls \in {"SYNC", "PROOF", "STATIC"} : HonestHit(i, t, cls)
    \/ \E i \in 1..Len(conns), cls \in {"SYNC", "PROOF", "STATIC"} : AdvHit(i, cls)

Spec == Init /\ [][Next]_vars

\* Safety: no honest node opens L toward Adv (it may hold nothing of L).
Safe == \A x \in served : x[2] \in Honest => Peer(conns[x[1]], x[2]) # Adv

\* Witnesses (expected to be violated: the state is reachable): two honest nodes open L on one
\* connection both ways.
NoPair == ~\E i \in 1..Len(conns) :
            /\ conns[i].d \in Honest /\ conns[i].l \in Honest
            /\ <<i, conns[i].d>> \in served /\ <<i, conns[i].l>> \in served
====
