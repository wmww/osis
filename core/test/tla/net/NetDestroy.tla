---- MODULE NetDestroy ----
(* Destruction and emptying of a thing T's own sync ID S (spec/sync-judgement.md §5, §4; spec/
   commits.md §5 Destruction, Forgetting). Readers a and b hold T's secrets and the delete key; K
   keeps S unread and judges nothing. a releases T: its release request q is logged under S. e is
   a content entry of T; <<"e", n>> for n > 0 is an encryption logged again (§4). The window is q's
   life: at its expiry q leaves every store with no tombstone. With Away, b acts only after it. *)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    MaxEnc,         \* highest encryption number of e (NoCap checks it is not reached)
    Away,           \* b is away for the whole window
    ToldGate,       \* §5 Emptying: a node deletes only once told (q held at a source, K)
    KeepReq,        \* proposed: emptying deletes no destroying request (it leaves at its expiry)
    Stand,          \* §4: logged again once; a delete of that encryption stands
    ForgetGate      \* §5: forget S only once no entry and no tombstone of it is known

Readers == {"a", "b"}
Blobs == {<<"q", 0>>} \cup ({"e"} \X (0..MaxEnc))
B(e) == e[1]
Q == <<"q", 0>>

VARIABLES
    store,      \* store[n]: n's own store of S
    known,      \* known[n]: K's store as n last read its stream
    delK,       \* delK[n]: n's entries deleted at K as n knows
    told,       \* told[n]: n holds T destroyed (an entry of q was held at K when it read it)
    forgot,     \* forgot[n]: n forgot S and T's secrets
    back,       \* back[n]: n took T back as never received, after its forget
    left,       \* left[n]: n left S untold
    again,      \* again[n]: times n logged e again
    enc,        \* next fresh encryption number of e
    storeK, tombK,
    released, qExpired,
    missed,     \* a node read K's stream inside the window and was not told
    badDel,     \* an honest delete of e at K while K held no q
    badForget   \* a forget while K's stream showed an entry or a tombstone was known
vars == <<store, known, delK, told, forgot, back, left, again, enc, storeK, tombK, released, qExpired, missed, badDel, badForget>>

Init ==
    /\ store = [n \in Readers |-> {<<"e", 0>>}]
    /\ known = [n \in Readers |-> {<<"e", 0>>}]
    /\ delK = [n \in Readers |-> {}]
    /\ told = [n \in Readers |-> FALSE]
    /\ forgot = [n \in Readers |-> FALSE]
    /\ back = [n \in Readers |-> FALSE]
    /\ left = [n \in Readers |-> FALSE]
    /\ again = [n \in Readers |-> 0]
    /\ enc = 1
    /\ storeK = {<<"e", 0>>} /\ tombK = {}
    /\ released = FALSE /\ qExpired = FALSE
    /\ missed = FALSE /\ badDel = FALSE /\ badForget = FALSE

Held(n) == {B(e) : e \in store[n]}
KnownB(n) == {B(e) : e \in known[n]}
Active(n) == ~left[n] /\ (n = "b" /\ Away => qExpired)
\* n judges T destroyed: emptying applies
Destroyed(n) == IF ToldGate THEN told[n] ELSE told[n] \/ "q" \in Held(n)

(* ---- honest steps ---- *)
Sync(n) ==
    LET d == (delK[n] \cup ((known[n] \cup store[n]) \cap tombK)) \ storeK IN
    /\ Active(n) /\ ~forgot[n]
    /\ known[n] # storeK \/ d # delK[n] \/ (Q \in storeK /\ ~told[n] /\ ~back[n])
    /\ known' = [known EXCEPT ![n] = storeK]
    /\ delK' = [delK EXCEPT ![n] = d]
    /\ told' = [told EXCEPT ![n] = @ \/ (Q \in storeK /\ ~back[n])]
    /\ missed' = (missed \/ (released /\ ~qExpired /\ Q \notin storeK /\ ~told[n] /\ ~back[n]
                            /\ \E m \in Readers : Q \in known[m]))
    /\ UNCHANGED <<store, forgot, back, left, again, enc, storeK, tombK, released, qExpired, badDel, badForget>>

\* K pulls what it lacks of n's store (a tombstoned blob ID is refused, code 6).
PullK(n, e) ==
    /\ Active(n) /\ e \in store[n] \ storeK
    /\ IF e \in tombK
       THEN /\ e \notin delK[n]
            /\ delK' = [delK EXCEPT ![n] = @ \cup {e}]
            /\ UNCHANGED storeK
       ELSE /\ storeK' = storeK \cup {e}
            /\ UNCHANGED delK
    /\ UNCHANGED <<store, known, told, forgot, back, left, again, enc, tombK, released, qExpired, missed, badDel, badForget>>

\* n fetches what K showed and it lacks; after its forget, an e arriving is T taken back as never received.
Fetch(n, e) ==
    /\ Active(n) /\ e \in known[n] \cap storeK /\ B(e) \notin Held(n)
    /\ ~Destroyed(n) \/ B(e) = "q"
    /\ IF forgot[n]
       THEN /\ B(e) = "e"
            /\ forgot' = [forgot EXCEPT ![n] = FALSE] /\ back' = [back EXCEPT ![n] = TRUE]
       ELSE UNCHANGED <<forgot, back>>
    /\ store' = [store EXCEPT ![n] = @ \cup {e}]
    /\ UNCHANGED <<known, delK, told, left, again, enc, storeK, tombK, released, qExpired, missed, badDel, badForget>>

\* Emptying: n, judging T destroyed, drops its own entries and deletes at K every entry its stream showed.
DropOwn(n) ==
    /\ Active(n) /\ Destroyed(n) /\ ~back[n] /\ \E e \in store[n] : B(e) = "e"
    /\ store' = [store EXCEPT ![n] = {e \in @ : B(e) # "e"}]
    /\ UNCHANGED <<known, delK, told, forgot, back, left, again, enc, storeK, tombK, released, qExpired, missed, badDel, badForget>>
Empty(n, e) ==
    /\ Active(n) /\ Destroyed(n) /\ ~back[n] /\ ~forgot[n]
    /\ e \in known[n] /\ e \in storeK
    /\ KeepReq => B(e) # "q"
    /\ storeK' = storeK \ {e} /\ tombK' = tombK \cup {e}
    /\ delK' = [delK EXCEPT ![n] = @ \cup {e}]
    /\ badDel' = (badDel \/ (B(e) = "e" /\ Q \notin storeK /\ ~qExpired))
    /\ UNCHANGED <<store, known, told, forgot, back, left, again, enc, released, qExpired, missed, badForget>>

\* §4: n, holding T alive, logs e again once past a delete at K.
LogAgain(n) ==
    /\ Active(n) /\ ~Destroyed(n) /\ "e" \in Held(n) /\ "e" \notin KnownB(n)
    /\ \A e \in store[n] : B(e) = "e" => e \in delK[n]
    /\ Stand => again[n] = 0
    /\ enc <= MaxEnc
    /\ store' = [store EXCEPT ![n] = {e \in @ : B(e) # "e"} \cup {<<"e", enc>>}]
    /\ enc' = enc + 1
    /\ again' = [again EXCEPT ![n] = @ + 1]
    /\ UNCHANGED <<known, delK, told, forgot, back, left, storeK, tombK, released, qExpired, missed, badDel, badForget>>

\* §5: told, n forgets S (and T's secrets) once its source is heard out with no entry and no tombstone known.
Forget(n) ==
    /\ Active(n) /\ told[n] /\ ~forgot[n] /\ ~back[n] /\ store[n] \cap ({"e"} \X (0..MaxEnc)) = {}
    /\ known[n] = storeK
    /\ ForgetGate => known[n] = {} /\ delK[n] \cap tombK = {}
    /\ forgot' = [forgot EXCEPT ![n] = TRUE]
    /\ store' = [store EXCEPT ![n] = {}]
    /\ delK' = [delK EXCEPT ![n] = {}]
    /\ known' = [known EXCEPT ![n] = {}]
    /\ badForget' = (badForget \/ storeK # {} \/ delK[n] \cap tombK # {})
    /\ UNCHANGED <<told, back, left, again, enc, storeK, tombK, released, qExpired, missed, badDel>>

\* §5 Untold: past the window, never told, n leaves S deleting nothing.
Untold(n) ==
    /\ Active(n) /\ qExpired /\ ~told[n] /\ ~back[n] /\ ~forgot[n]
    /\ "e" \in KnownB(n) \/ (\E e \in store[n] : e \in delK[n])  \* it meets a delete it cannot explain
    /\ left' = [left EXCEPT ![n] = TRUE]
    /\ UNCHANGED <<store, known, delK, told, forgot, back, again, enc, storeK, tombK, released, qExpired, missed, badDel, badForget>>

Honest == \E n \in Readers :
    \/ Sync(n) \/ DropOwn(n) \/ LogAgain(n) \/ Forget(n)
    \/ \E e \in Blobs : PullK(n, e) \/ Fetch(n, e) \/ Empty(n, e)

(* ---- the world ---- *)
Release ==
    /\ ~released /\ released' = TRUE
    /\ store' = [store EXCEPT !["a"] = @ \cup {Q}]
    /\ UNCHANGED <<known, delK, told, forgot, back, left, again, enc, storeK, tombK, qExpired, missed, badDel, badForget>>
ExpireQ ==
    /\ released /\ ~qExpired /\ qExpired' = TRUE
    /\ \A n \in Readers : told[n] \/ (n = "b" /\ Away)    \* the window outlasts a connected node's reading
    /\ store' = [n \in Readers |-> store[n] \ {Q}]
    /\ known' = [n \in Readers |-> known[n] \ {Q}]
    /\ storeK' = storeK \ {Q} /\ tombK' = tombK \ {Q}
    /\ UNCHANGED <<delK, told, forgot, back, left, again, enc, released, missed, badDel, badForget>>
ExpireTomb(e) ==
    /\ e \in tombK /\ \A n \in Readers : e \notin known[n] \/ ~Active(n)
    /\ tombK' = tombK \ {e}
    /\ UNCHANGED <<store, known, delK, told, forgot, back, left, again, enc, storeK, released, qExpired, missed, badDel, badForget>>

Next == Honest \/ Release \/ ExpireQ \/ (\E e \in Blobs : ExpireTomb(e)) \/ (\E n \in Readers : Untold(n))
Fair == \A n \in Readers :
    /\ SF_vars(Sync(n)) /\ WF_vars(DropOwn(n)) /\ WF_vars(LogAgain(n)) /\ WF_vars(Forget(n)) /\ WF_vars(Untold(n))
    /\ \A e \in Blobs : WF_vars(PullK(n, e)) /\ WF_vars(Fetch(n, e)) /\ WF_vars(Empty(n, e))
Spec == Init /\ [][Next]_vars /\ Fair /\ WF_vars(Release)

(* ---- properties ---- *)
Quiet == ~ENABLED Honest
\* §5 Telling: nothing of S is deleted at K while K holds no destroying request.
ToldBeforeEmptied == ~badDel
\* the window: a node reading K's stream while q lives is told (no destroying request deleted inside it).
NoMiss == ~missed
\* a node forgets S only when no entry and no tombstone of it is known there.
ForgetEmpty == ~badForget
\* no loop: a node logs e again at most once (no change of ground in this model).
Bounded == \A n \in Readers : again[n] <= 1
NoCap == enc <= MaxEnc
\* a node present in the window ends without T; one away holds it or left (stated limit).
QuietDone == Quiet /\ released =>
    \A n \in Readers : (n = "b" /\ Away) \/ ("e" \notin Held(n) /\ ~back[n])
Settles == <>[]Quiet
====
