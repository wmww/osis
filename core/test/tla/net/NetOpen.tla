---- MODULE NetOpen ----
(* Who may open sync ID L on a connection (issues/net-6c-plan.md): the 6c rule that each side
   opens L only on its own proof that the peer may hold L, and the open signature's domain.
   Honest nodes are readers (hold L's sync secrets, the proof value and a key actor whose static
   entry L's head lists; they record an older step under another sync key, which their walk may
   Hit) or stores (hold L sync-only at the head: its sync key and the proof value). Adv is a
   removed sync holder: it holds the older step's sync secret and every public value of L (sync
   and claim public keys, static entries, claim sets), and no secret of the head. Adv picks its
   Hello challenges from those it has seen (the other side's of the same connection included),
   dials anyone and is dialed by anyone, shows every credential it can compute, answers any Hit
   with a tag and any token it holds, and replays any signature, Hit or tag it was sent, on any
   connection. A token is a signature, or a Hit or tag keyed by a secret match value (bound to
   its sender's side always, as Hits and tags are); it is modelled by its key, side, the
   verifier's challenge and the listener's key (weaker than a Hit's binding of both challenges).
   A rule of the design is a flag. *)
EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Nodes, Adv, Role,       \* Role[n] \in {"reader", "store"} for n # Adv
    MaxConn,
    SideByte,               \* the open signature's digest holds the signer's side (dialer 0, listener 1)
    AnswerSig,              \* a tester opens only on J or the replier's proof (answer signature, or a secret tag)
    ListenerSigns,          \* FALSE: a listener never makes an open signature (the rejected option)
    ProofSecret,            \* the proof's match value derives from the sync secret, not the public sync key
    NewestOnly              \* an answer signature counts only by the newest step's sync key

Honest == Nodes \ {Adv}
None == [k |-> "none"]

\* Credential classes: SYNC (a store's head sync key), OLD (an older step's sync key: a removed
\* holder's head, which a reader's walk may Hit), PROOF (the proof a reader shows, its match from
\* the head's sync secret), STATIC (a key actor's static entry, signed as a Static item by the key
\* actor; a claim is alike). SYNC, OLD and STATIC are public match values: a tag on them proves
\* nothing.
Classes == {"SYNC", "OLD", "PROOF", "STATIC"}
KeyOf(cls) == CASE cls = "STATIC" -> "ka" [] cls = "OLD" -> "old" [] cls = "PROOF" -> "proof"
                [] OTHER -> "sync"
\* The key of the replier's proof answering a Hit on cls: the tag itself for the proof, else the
\* open signature by the sync key of the step the open is made at.
AnsKey(cls) == CASE cls = "PROOF" -> "proof" [] cls = "OLD" -> "old" [] OTHER -> "sync"
Secret(k) == k = "proof"
Holds(n) == IF n = Adv THEN {"old"} \cup (IF ProofSecret THEN {} ELSE {"proof"})
            ELSE IF Role[n] = "reader" THEN {"sync", "old", "ka", "proof"} ELSE {"sync", "proof"}
\* What a filter shows (to every connection: the worst case for read credentials too). Adv shows
\* what it can compute: its head (OLD) and every public value.
Shows(n) == IF n = Adv THEN {"SYNC", "OLD", "STATIC"} \cup (IF ProofSecret THEN {} ELSE {"PROOF"})
            ELSE IF Role[n] = "store" THEN {"SYNC", "STATIC"} ELSE {"PROOF", "STATIC"}
\* What a node tests against a peer's filter: a reader its sync key at stores (the newest step's,
\* and by its walk an older step's) and its key actor's entry anywhere; a store its head's sync
\* key and its proof.
Tests(n) == IF Role[n] = "reader" THEN {"SYNC", "OLD", "STATIC"} ELSE {"SYNC", "PROOF"}
\* J: a reader judges a peer by the rosters it holds (J counts sync: a store's account holds
\* sync on L); a store holds no roster. Adv's actors hold no role on L now.
J(t, r) == Role[t] = "reader" /\ r # Adv

VARIABLES conns, served, known, seen, next
vars == <<conns, served, known, seen, next>>

Side(c, n) == IF n = c.d THEN 0 ELSE 1
Peer(c, n) == IF n = c.d THEN c.l ELSE c.d
Ch(c, n) == IF n = c.d THEN c.cd ELSE c.cl
Sig(k, sd, ch, lk) == [k |-> k, sd |-> sd, ch |-> ch, lk |-> lk]
\* An honest node makes a token only where the rule lets it (a Hit or tag always).
CanSign(n, c, k) == ListenerSigns \/ Secret(k) \/ n = c.d
\* The tokens Adv can make on c for verifier n: by the keys it holds.
Forge(c, n) == {Sig(k, Side(c, Adv), Ch(c, n), c.l) : k \in Holds(Adv)}
\* Verified by n on c as made by the other side with key k.
Valid(s, k, c, n) ==
    /\ s.k = k
    /\ (SideByte \/ Secret(k)) => s.sd = Side(c, Peer(c, n))
    /\ s.ch = Ch(c, n)
    /\ s.lk = c.l
    /\ CanSign(Peer(c, n), c, k)
\* Tester t opens toward its peer on answer a to its Hit on cls.
Opens(t, p, cls, a, c) ==
    \/ ~AnswerSig
    \/ J(t, p)
    \/ /\ a # None /\ Valid(a, AnsKey(cls), c, t)
       /\ NewestOnly => AnsKey(cls) # "old"

Init ==
    /\ conns = <<>>
    /\ served = {}
    /\ known = {}
    /\ seen = {}
    /\ next = 1

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
    /\ UNCHANGED <<served, known>>

\* Honest t on connection i Hits a credential the peer's filter shows, its token made over its
\* own side, the peer's challenge and the listener's key. An honest peer verifies it, opens
\* (serves t) and answers with its own proof where it holds the key; t opens on Opens. Adv
\* collects the token and answers with a tag and any token it holds or makes.
HonestHit(i, t, cls) ==
    LET c == conns[i]
        p == Peer(c, t)
        s == Sig(KeyOf(cls), Side(c, t), Ch(c, p), c.l)
    IN
    /\ t \in Honest /\ t \in {c.d, c.l}
    /\ <<i, t>> \notin served
    /\ cls \in Tests(t) /\ cls \in Shows(p) /\ KeyOf(cls) \in Holds(t)
    /\ CanSign(t, c, KeyOf(cls))
    /\ IF p = Adv
       THEN /\ known' = known \cup {s}
            /\ \E a \in known' \cup Forge(c, t) \cup {None} :
                 served' = IF Opens(t, p, cls, a, c) THEN served \cup {<<i, t>>} ELSE served
       ELSE LET a == IF AnsKey(cls) \in Holds(p) /\ CanSign(p, c, AnsKey(cls))
                     THEN Sig(AnsKey(cls), Side(c, p), Ch(c, t), c.l) ELSE None
            IN /\ served' = served \cup {<<i, p>>}
                              \cup (IF Opens(t, p, cls, a, c) THEN {<<i, t>>} ELSE {})
               /\ UNCHANGED known
    /\ UNCHANGED <<conns, seen, next>>

\* Adv Hits honest h with any token it holds or makes, on a credential h's filter shows; h opens
\* L toward Adv when it verifies, and answers with its own proof (which Adv keeps).
AdvHit(i, cls) ==
    LET c == conns[i]
        h == Peer(c, Adv)
    IN
    /\ Adv \in {c.d, c.l}
    /\ cls \in Shows(h)
    /\ \E s \in known \cup Forge(c, h) :
        /\ Valid(s, KeyOf(cls), c, h)
        /\ served' = served \cup {<<i, h>>}
        /\ known' = IF AnsKey(cls) \in Holds(h) /\ CanSign(h, c, AnsKey(cls))
                    THEN known \cup {Sig(AnsKey(cls), Side(c, h), Ch(c, Adv), c.l)} ELSE known
    /\ UNCHANGED <<conns, seen, next>>

Next ==
    \/ \E d, l \in Nodes : Connect(d, l)
    \/ \E i \in 1..Len(conns), t \in Honest, cls \in Classes : HonestHit(i, t, cls)
    \/ \E i \in 1..Len(conns), cls \in Classes : AdvHit(i, cls)

Spec == Init /\ [][Next]_vars

\* Safety: no honest node opens L toward Adv (it may hold nothing of L now).
Safe == \A x \in served : x[2] \in Honest => Peer(conns[x[1]], x[2]) # Adv

\* Witnesses (expected to be violated: the state is reachable): two honest nodes open L on one
\* connection both ways.
NoPair == ~\E i \in 1..Len(conns) :
            /\ conns[i].d \in Honest /\ conns[i].l \in Honest
            /\ <<i, conns[i].d>> \in served /\ <<i, conns[i].l>> \in served
====
