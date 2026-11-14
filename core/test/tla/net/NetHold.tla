---- MODULE NetHold ----
(* Hold, log and delete per sync ID S (spec/sync-judgement.md §2-§4, spec/sync-compaction.md §1,
   spec/sync-ids.md §6, spec/sync-streams.md §4 Refused). Two honest readers r1, r2 (writers of
   S), a node K keeping S unread, optionally a hostile writer H deleting anything at K.
   Bodies: b, a write on aspect A authored by r2; c, r1's snapshot of A covering b; x, a role
   commit by r2 under which c is invalid. A blob ID is <<body, n>>: n > 0 is a fresh encryption
   logged again. r2, b's author, keeps b as local data under r1's cover (spec/sync-compaction.md
   §1 Own bodies), but b's entries leave its log (§3 Own store): no stream from r2 lists them. K takes what it pulls from a reader's store unless tombstoned (code 6) and Deletes;
   it judges nothing. A reader learns K's store only from K's stream (Sync: the stream read to
   its end). With KeepB, b is must-hold whatever covers it (a kept delta, a lasting header, or a
   delta on another aspect no snapshot covers). With XFall, x itself falls once (a later role
   change every reader learns at once): c is valid again, and a reader that dropped it as invalid
   counts it never received and fetches it where present. With MaxRestart, readers restart; the
   stand and the deletes seen live in the record (durable). Each rule is a flag; a rule removed
   must fail for its stated reason (cfg comments). *)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    MaxEnc,         \* highest encryption number (bounds logging again; NoCap checks it is not reached)
    MaxHead,        \* head moves at K (a Register)
    WithX,          \* x may be written
    MaxH,           \* H, a hostile writer, deletes any entry at K at any time, up to MaxH times (0: no H)
    ReadersMeet,    \* readers pull each other directly (else only through K)
    TombExpire,     \* K's tombstones may expire within the run (TOMBSTONE_LIFETIME passes)
    Stand,          \* §4: a delete of an encryption logged again stands while the ground is unchanged
    StandHead,      \* §4: the ground includes K's head
    StandFall,      \* §4: the ground includes a held part on the aspect falling here
    FreshEnc,       \* §4: logged again as a fresh blob ID
    KnownGround,    \* §3 Deletes: the carrier is read from K's stream, not from what this node holds or sent
    ReadersOnly,    \* §3 Between readers: no Delete between readers
    RoleFirst,      \* §3 Role entries first: deletes and logging again wait for K to take this node's role commits
    SnapClause,     \* §2 established uncovered: a snapshot under S this node does not hold blocks it
    InvalidBlocks,  \* control: ... counting one this node dropped as invalid (§2: it does not count)
    FallAny,        \* §4: c judged invalid here counts as a fall whether held valid before or arriving invalid
    DelRoleView,    \* §3 Role entries first: a delete waits while K's stream shows a role commit this node lacks
    Dups,           \* compaction §1 Duplicates: of two entries of one body at K, a delete-key holder deletes the higher
    Cap,            \* K's cap on entries of b and c (x, a role entry, counts toward none); 9: none
    FullCarrier,    \* §3 Deletes: at a source full for S, a carrier it lacks counts as held
    OwnLog,         \* §3 Own store: an entry covered and dropped leaves the log even where its body stays local
    KeepB,          \* b is must-hold whatever snapshot covers it
    MustNoDrop,     \* §3 Own store, Deletes: covered and dropped is a may-hold body only (a must-hold body never is)
    XFall,          \* x falls once within the run
    InvalidKeep,    \* §2 may-hold, §3 Deletes: a body dropped as invalid is never deleted at a peer
    Fixpoint,       \* §3 Driven by events: judging runs to a fixpoint before acting (FALSE: c's verdict lags a step)
    MaxRestart,     \* reader restarts
    StandDurable    \* §4: the stand's state and the deletes seen live in the peer's record, durably

Readers == {"r1", "r2"}
Bodies == {"b", "c", "x"}
Blobs == Bodies \X (0..MaxEnc)
B(e) == e[1]
NoGround == <<99, 99>>

VARIABLES
    store,      \* store[r]: blob IDs in reader r's log of S (what its stream lists)
    unlog,      \* unlog[r]: r's entries out of its log whose body it keeps as local data (Own bodies)
    dropT,      \* dropT[r]: bodies r dropped (its own tombstones: it knows their entries, holds no bytes)
    falls,      \* falls[r]: times c fell at r (held valid, then invalid)
    known,      \* known[r]: K's store as r last read K's stream
    kHead,      \* kHead[r]: K's head as r last read it
    delK,       \* delK[r]: r's entries deleted at K as r knows (a Deleted event, or code 6)
    againG,     \* againG[r][d]: the ground (head, falls) at r's last logging again of d
    againN,     \* againN[r][d]: times r logged d again
    enc,        \* enc[d]: next fresh encryption number of d
    storeK, tombK, headK,
    written,    \* of {"c", "x"}
    hN,         \* H's deletes so far
    dlog,       \* every entry deleted at K in the run (its stream's Deleted events, read in order)
    full,       \* K is full for S (refused a pulled entry for room, code 12)
    refused,    \* entries K refused for room while full (not fetched again while full)
    kFull,      \* kFull[r]: K's full flag as r last read it (event 2 in K's stream)
    badDel,     \* an honest delete took b at K while K held no entry of c
    xFell,      \* x fell (XFall)
    cAtK,       \* K held an entry of c at some point
    vc,         \* vc[r]: c's validity as r last judged it (only without Fixpoint)
    nRestart    \* restarts so far
vars == <<store, unlog, dropT, falls, known, kHead, delK, againG, againN, enc, storeK, tombK, headK, written, hN, dlog, full, refused, kFull, badDel, xFell, cAtK, vc, nRestart>>
ext == <<xFell, cAtK, vc, nRestart>>

Hostile == MaxH > 0
Held(r) == {B(e) : e \in store[r] \cup unlog[r]}
KB == {B(e) : e \in storeK}
KnownB(r) == {B(e) : e \in known[r]}
Other(r) == IF r = "r1" THEN "r2" ELSE "r1"

Init ==
    /\ store = [r \in Readers |-> IF r = "r2" THEN {<<"b", 0>>} ELSE {}]
    /\ unlog = [r \in Readers |-> {}]
    /\ dropT = [r \in Readers |-> {}]
    /\ falls = [r \in Readers |-> 0]
    /\ known = [r \in Readers |-> {}]
    /\ kHead = [r \in Readers |-> 0]
    /\ delK = [r \in Readers |-> {}]
    /\ againG = [r \in Readers |-> [d \in Bodies |-> NoGround]]
    /\ againN = [r \in Readers |-> [d \in Bodies |-> 0]]
    /\ enc = [d \in Bodies |-> 1]
    /\ storeK = {} /\ tombK = {} /\ headK = 0
    /\ written = {} /\ hN = 0 /\ dlog = {} /\ badDel = FALSE
    /\ full = FALSE /\ refused = {} /\ kFull = [r \in Readers |-> FALSE]
    /\ xFell = FALSE /\ cAtK = FALSE /\ vc = [r \in Readers |-> TRUE] /\ nRestart = 0

(* Judgement at r (spec/sync-judgement.md §2). c is valid at r while r holds no x. *)
Valid(r) == "x" \notin Held(r) \/ xFell
Covered(r) == "c" \in Held(r) /\ (IF Fixpoint THEN Valid(r) ELSE vc[r])
\* covered and dropped (§3): a may-hold body under a held valid snapshot
CovDrop(r) == Covered(r) /\ (MustNoDrop => ~KeepB)
UnheldSnap(r) ==
    /\ SnapClause /\ "c" \notin Held(r)
    /\ IF "c" \in dropT[r] THEN InvalidBlocks ELSE "c" \in KnownB(r)
MustHold(r, d) ==
    /\ d \in Held(r)
    /\ d = "b" => KeepB \/ (~Covered(r) /\ ~UnheldSnap(r))  \* kept, or established uncovered
Read(r) == IF "b" \in Held(r) \/ Covered(r) THEN "w" ELSE "none"

(* r's store becomes s: c held beside x is invalid and dropped at once (spec/permissions.md §6);
   c held valid before fell: r forgets its own tombstone of b (spec/sync-compaction.md §1, A
   snapshot turning invalid) and fetches it where present; b kept local is must-hold again and
   its entries return to r's log. *)
Settle(r, s) ==
    LET h == {B(e) : e \in s \cup unlog[r]}
        wasValid == Covered(r)
    IN IF "c" \in h /\ "x" \in h /\ ~xFell
       THEN [st |-> {e \in s : B(e) # "c"} \cup (IF wasValid THEN unlog[r] ELSE {}),
             ul |-> IF wasValid THEN {} ELSE unlog[r],
             dt |-> (dropT[r] \cup {"c"}) \ (IF wasValid THEN {"b"} ELSE {}),
             fl |-> falls[r] + (IF wasValid \/ (FallAny /\ "c" \notin dropT[r]) THEN 1 ELSE 0)]
       ELSE [st |-> s, ul |-> unlog[r], dt |-> dropT[r], fl |-> falls[r]]
SetR(r, n) ==
    /\ store' = [store EXCEPT ![r] = n.st]
    /\ unlog' = [unlog EXCEPT ![r] = n.ul]
    /\ dropT' = [dropT EXCEPT ![r] = n.dt]
    /\ falls' = [falls EXCEPT ![r] = n.fl]

\* §3 Role entries first: K lacks a role commit of r's store that is neither present nor deleted there.
RoleWait(r) == RoleFirst /\ ~kFull[r] /\ \E e \in store[r] : B(e) = "x" /\ e \notin known[r] /\ e \notin delK[r]
Counted(s) == Cardinality({e \in s : B(e) # "x"})
\* an entry leaving K: room grew, K sends full false and pulls S again from the start
Leave(e) ==
    /\ storeK' = storeK \ {e} /\ tombK' = tombK \cup {e} /\ dlog' = dlog \cup {e}
    /\ IF full /\ B(e) # "x" THEN full' = FALSE /\ refused' = {} ELSE UNCHANGED <<full, refused>>
Ground(r) == <<IF StandHead THEN kHead[r] ELSE 0, IF StandFall THEN falls[r] ELSE 0>>

(* ---- honest steps ---- *)
Sync(r) ==
    LET d == (delK[r] \cup ((known[r] \cup store[r] \cup unlog[r]) \cap dlog)) \ storeK IN
    /\ known[r] # storeK \/ kHead[r] # headK \/ d # delK[r] \/ kFull[r] # full
    /\ known' = [known EXCEPT ![r] = storeK]
    /\ kFull' = [kFull EXCEPT ![r] = full]
    /\ kHead' = [kHead EXCEPT ![r] = headK]
    /\ delK' = [delK EXCEPT ![r] = d]
    /\ UNCHANGED <<store, unlog, dropT, falls, againG, againN, enc, storeK, tombK, headK, written, badDel, hN, full, refused, dlog>>
    /\ UNCHANGED ext

\* r fetches an entry K's stream showed, or (ReadersMeet) one another reader holds; not one it dropped.
Take(r, e) ==
    /\ B(e) \notin Held(r) \cup dropT[r]
    /\ IF Fixpoint THEN SetR(r, Settle(r, store[r] \cup {e}))
       ELSE /\ store' = [store EXCEPT ![r] = @ \cup {e}]
            /\ UNCHANGED <<unlog, dropT, falls>>
    /\ UNCHANGED <<known, kHead, delK, againG, againN, enc, storeK, tombK, headK, written, badDel, hN, full, refused, kFull, dlog>>
    /\ UNCHANGED ext
\* without Fixpoint: r judges what it took, a step later
Judge(r) ==
    /\ ~Fixpoint
    /\ LET n == Settle(r, store[r]) IN
       /\ n.st # store[r] \/ n.ul # unlog[r] \/ n.dt # dropT[r] \/ vc[r] # Valid(r)
       /\ SetR(r, n)
    /\ vc' = [vc EXCEPT ![r] = Valid(r)]
    /\ UNCHANGED <<known, kHead, delK, againG, againN, enc, storeK, tombK, headK, written, badDel, hN, full, refused, kFull, dlog, xFell, cAtK, nRestart>>
Fetch(r, e) == e \in known[r] \cap storeK /\ Take(r, e)
PullR(r, e) == ReadersMeet /\ e \in store[Other(r)] /\ Take(r, e)

(* §3 Own store: b covered and dropped under a held valid c leaves r's log. r1 drops it (its own
   tombstone); r2, its author, keeps the body as local data only (spec/sync-compaction.md §1 Own
   bodies: it wrote no cover), so no stream from r2 lists it. *)
DropB(r) ==
    /\ CovDrop(r) /\ \E e \in store[r] : B(e) = "b"
    /\ store' = [store EXCEPT ![r] = {e \in @ : B(e) # "b"}]
    /\ IF r = "r2"
       THEN /\ OwnLog
            /\ unlog' = [unlog EXCEPT ![r] = @ \cup {e \in store[r] : B(e) = "b"}]
            /\ UNCHANGED dropT
       ELSE /\ dropT' = [dropT EXCEPT ![r] = @ \cup {"b"}]
            /\ UNCHANGED unlog
    /\ UNCHANGED <<falls, known, kHead, delK, againG, againN, enc, storeK, tombK, headK, written, badDel, hN, full, refused, kFull, dlog>>
    /\ UNCHANGED ext

\* K pulls what it lacks of r's store; a tombstoned blob ID is refused, code 6 (deleted there).
PullK(r, e) ==
    /\ e \in store[r] \ storeK
    /\ IF e \in tombK
       THEN /\ e \notin delK[r]
            /\ delK' = [delK EXCEPT ![r] = @ \cup {e}]
            /\ UNCHANGED <<storeK, full, refused>>
       ELSE IF B(e) # "x" /\ Counted(storeK) >= Cap
       THEN /\ e \notin refused
            /\ full' = TRUE /\ refused' = refused \cup {e}
            /\ UNCHANGED <<storeK, delK>>
       ELSE /\ storeK' = storeK \cup {e}
            /\ UNCHANGED <<delK, full, refused>>
    /\ cAtK' = (cAtK \/ (B(e) = "c" /\ e \notin tombK /\ (Counted(storeK) < Cap \/ B(e) = "x")))
    /\ UNCHANGED <<xFell, vc, nRestart>>
    /\ UNCHANGED <<store, unlog, dropT, falls, known, kHead, againG, againN, enc, tombK, headK, written, badDel, hN, kFull, dlog>>

\* §3 Deletes, spec/sync-compaction.md §1 Carriers and Duplicates: r deletes at K an entry K's
\* stream showed, covered by its held valid c once K's stream shows c (the carrier), or the higher
\* of two entries of one body; signed for K's head as r knows it.
Delete(r, e) ==
    /\ e \in known[r] /\ e \in storeK
    /\ kHead[r] = headK
    /\ ~RoleWait(r)
    /\ DelRoleView => ("x" \in KnownB(r) => "x" \in Held(r))
    /\ \/ /\ B(e) = "b" /\ CovDrop(r)
          /\ IF KnownGround THEN "c" \in KnownB(r) \/ (FullCarrier /\ kFull[r]) ELSE "c" \in Held(r)
       \/ Dups /\ \E f \in known[r] : B(f) = B(e) /\ f[2] < e[2]
       \/ ~InvalidKeep /\ B(e) = "c" /\ "c" \in dropT[r]   \* control: deletes what it dropped as invalid
    /\ Leave(e)
    /\ badDel' = (badDel \/ (B(e) = "b" /\ "c" \notin KB /\ ~full /\ ~(FullCarrier /\ kFull[r])))
    /\ store' = IF ReadersOnly THEN store ELSE [store EXCEPT ![Other(r)] = @ \ {e}]
    /\ unlog' = IF ReadersOnly THEN unlog ELSE [unlog EXCEPT ![Other(r)] = @ \ {e}]
    /\ delK' = [delK EXCEPT ![r] = @ \cup {e}]     \* a deleter knows its own delete
    /\ UNCHANGED <<dropT, falls, known, kHead, againG, againN, enc, headK, written, hN, kFull>>
    /\ UNCHANGED ext

\* §4: past a delete at K that does not stand (§3 Neither), r logs d again once per ground.
LogAgain(r, d) ==
    /\ MustHold(r, d)
    /\ d \notin KnownB(r)
    /\ \A e \in store[r] : B(e) = d => e \in delK[r]
    /\ ~RoleWait(r)
    /\ Stand => againG[r][d] # Ground(r)
    /\ enc[d] <= MaxEnc
    /\ LET n == IF FreshEnc THEN enc[d] ELSE 0 IN
       /\ store' = [store EXCEPT ![r] = {e \in @ : B(e) # d} \cup {<<d, n>>}]
       /\ enc' = IF FreshEnc THEN [enc EXCEPT ![d] = @ + 1] ELSE enc
    /\ againG' = [againG EXCEPT ![r][d] = Ground(r)]
    /\ againN' = [againN EXCEPT ![r][d] = @ + 1]
    /\ UNCHANGED <<unlog, dropT, falls, known, kHead, delK, storeK, tombK, headK, written, badDel, hN, full, refused, kFull, dlog>>
    /\ UNCHANGED ext

Honest ==
    \E r \in Readers :
        \/ Sync(r) \/ DropB(r)
        \/ \E e \in Blobs : Fetch(r, e) \/ PullR(r, e) \/ PullK(r, e) \/ Delete(r, e)
        \/ \E d \in Bodies : LogAgain(r, d)
        \/ Judge(r)

(* ---- the world ---- *)
WriteC ==
    /\ "c" \notin written /\ "b" \in Held("r1")
    /\ written' = written \cup {"c"}
    /\ SetR("r1", Settle("r1", store["r1"] \cup {<<"c", 0>>}))
    /\ UNCHANGED <<known, kHead, delK, againG, againN, enc, storeK, tombK, headK, badDel, hN, full, refused, kFull, dlog>>
    /\ UNCHANGED ext
WriteX ==
    /\ WithX /\ "x" \notin written
    /\ written' = written \cup {"x"}
    /\ SetR("r2", Settle("r2", store["r2"] \cup {<<"x", 0>>}))
    /\ UNCHANGED <<known, kHead, delK, againG, againN, enc, storeK, tombK, headK, badDel, hN, full, refused, kFull, dlog>>
    /\ UNCHANGED ext
MoveHead ==
    /\ headK < MaxHead /\ headK' = headK + 1
    /\ UNCHANGED <<store, unlog, dropT, falls, known, kHead, delK, againG, againN, enc, storeK, tombK, written, badDel, hN, full, refused, kFull, dlog>>
    /\ UNCHANGED ext
HDelete(e) ==
    /\ hN < MaxH /\ e \in storeK
    /\ Leave(e) /\ hN' = hN + 1
    /\ UNCHANGED <<store, unlog, dropT, falls, known, kHead, delK, againG, againN, enc, headK, written, badDel, kFull>>
    /\ UNCHANGED ext
Expire(e) ==
    /\ TombExpire /\ e \in tombK
    /\ \A r \in Readers : e \notin known[r]     \* every reader read K's stream past the delete within TOMBSTONE_LIFETIME
    /\ tombK' = tombK \ {e}
    /\ UNCHANGED <<store, unlog, dropT, falls, known, kHead, delK, againG, againN, enc, storeK, headK, written, badDel, hN, full, refused, kFull, dlog>>
    /\ UNCHANGED ext

\* x falls (a later role change, learned by every reader at once): c valid again; a reader that
\* dropped it as invalid counts it never received (spec/permissions.md §6).
FallX ==
    /\ XFall /\ "x" \in written /\ ~xFell
    /\ xFell' = TRUE
    /\ dropT' = [r \in Readers |-> dropT[r] \ {"c"}]
    /\ vc' = [r \in Readers |-> TRUE]
    /\ UNCHANGED <<store, unlog, falls, known, kHead, delK, againG, againN, enc, storeK, tombK, headK, written, hN, dlog, full, refused, kFull, badDel, cAtK, nRestart>>
\* a reader restarts: with StandDurable nothing of the stand is lost (it lives in K's record).
Restart(r) ==
    /\ nRestart < MaxRestart
    /\ nRestart' = nRestart + 1
    /\ IF StandDurable THEN UNCHANGED <<againG, delK>>
       ELSE /\ againG' = [againG EXCEPT ![r] = [d \in Bodies |-> NoGround]]
            /\ delK' = [delK EXCEPT ![r] = {}]
    /\ UNCHANGED <<store, unlog, dropT, falls, known, kHead, againN, enc, storeK, tombK, headK, written, hN, dlog, full, refused, kFull, badDel, xFell, cAtK, vc>>

Next == Honest \/ WriteC \/ WriteX \/ MoveHead \/ FallX \/ \E e \in Blobs : HDelete(e) \/ Expire(e)
        \/ \E r \in Readers : Restart(r)
Fair == \A r \in Readers :
    /\ SF_vars(Sync(r)) /\ WF_vars(DropB(r))   \* SF: a stream is read within TOMBSTONE_LIFETIME
    /\ \A e \in Blobs : WF_vars(Fetch(r, e)) /\ WF_vars(PullR(r, e)) /\ WF_vars(PullK(r, e))
    /\ WF_vars(\E e \in Blobs : Delete(r, e))
    /\ WF_vars(\E d \in Bodies : LogAgain(r, d))
    /\ WF_vars(Judge(r))
Spec == Init /\ [][Next]_vars /\ Fair

(* ---- properties ---- *)
Quiet == ~ENABLED Honest
XLive == "x" \in written /\ ~xFell
\* c once x fell is claimed only if K ever held it (with none it stays gone, spec/permissions.md §6)
Needed(d) == CASE d = "b" -> KeepB \/ "c" \notin written \/ XLive
             [] d = "c" -> "c" \in written /\ ("x" \notin written \/ (xFell /\ cAtK))
             [] d = "x" -> "x" \in written

\* §4: per (reader, body) at most one logging again per change of ground (no loop).
Bounded == \A r \in Readers, d \in Bodies : againN[r][d] <= 1 + headK + falls[r]
\* the run's bound on encryptions was not what stopped a loop
NoCap == \A d \in Bodies : enc[d] <= MaxEnc
\* Carriers: an honest delete never takes b while K, not full, holds no entry of its cover.
Carried == ~Hostile => ~badDel   \* H may delete the cover at K behind a reader's view
\* nothing a reader needs is gone from every honest node and K.
NoLoss == \A d \in Bodies : Needed(d) => d \in Held("r1") \cup Held("r2") \cup KB
\* at quiet (no hostile node) every reader reads w, and K holds every needed body.
QuietAlike == (~Hostile /\ Quiet) =>
    /\ \A r \in Readers : Read(r) = "w"
    /\ \A r \in Readers : \A d \in {"b", "c"} : (Needed(d) /\ (d = "b" => KeepB)) => d \in Held(r)
    /\ \A d \in Bodies : Needed(d) => d \in KB
\* liveness (no hostile node): the system reaches quiet and stays.
Settles == <>[]Quiet
Probe == \A d \in Bodies : enc[d] <= 3
Probe2 == Cardinality(tombK) <= 3
====
