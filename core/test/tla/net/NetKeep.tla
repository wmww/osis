---- MODULE NetKeep ----
(* A node K keeping S unread follows its own grant (spec/sync-judgement.md §6): it holds sync
   secrets by epoch from boxes sealed to it, keeps its store while its synced group lists the
   thing, opens S only by the sync key of its head's step, is stranded (keeping its store) when
   the head moves to a step whose secret it lacks, and drops S on its removal notice or when
   unlisted. A granter rotates (a new step per sync epoch, boxing K unless it removed K) and
   registers steps at K; boxes, notices and Registers arrive in any order. *)
EXTENDS Naturals, FiniteSets

CONSTANTS
    MaxEp,          \* sync epochs after the first
    DropOnHead,     \* control: K drops its store on a head move to a step it holds no secret of
    OpenAny         \* control: K opens S by any sync secret it holds, not its head's

VARIABLES
    epoch,      \* the granter's newest sync epoch
    removedAt,  \* the epoch whose rotation removed K (MaxEp + 1: none)
    msgs,       \* in flight to K: [t |-> "box" | "rm", e |-> epoch]
    reg,        \* steps registered by the granter but not yet taken at K (Register in flight)
    secrets,    \* K's sync secrets by epoch
    head,       \* K's head step (step n bears epoch n's sync key)
    hasStore,   \* K keeps a nonempty store of S
    keeping,    \* K keeps S
    listed,     \* K's synced group lists the thing
    gotRm       \* K took its removal notice
vars == <<epoch, removedAt, msgs, reg, secrets, head, hasStore, keeping, listed, gotRm>>

None == MaxEp + 1

Init ==
    /\ epoch = 0 /\ removedAt = None
    /\ msgs = {} /\ reg = {}
    /\ secrets = {0} /\ head = 0
    /\ hasStore = TRUE /\ keeping = TRUE /\ listed = TRUE /\ gotRm = FALSE

\* the granter rotates: a new step; K boxed unless removed now or before (its removal notice sent)
Rotate(remove) ==
    /\ epoch < MaxEp
    /\ remove => removedAt = None
    /\ epoch' = epoch + 1
    /\ removedAt' = IF remove THEN epoch + 1 ELSE removedAt
    /\ msgs' = msgs \cup (IF remove THEN {[t |-> "rm", e |-> epoch + 1]}
                          ELSE IF removedAt = None THEN {[t |-> "box", e |-> epoch + 1]} ELSE {})
    /\ reg' = reg \cup {epoch + 1}
    /\ UNCHANGED <<secrets, head, hasStore, keeping, listed, gotRm>>

\* K takes a Register: steps are taken in order (a step whose prev is the head)
Register ==
    /\ keeping /\ (head + 1) \in reg
    /\ head' = head + 1 /\ reg' = reg \ {head + 1}
    /\ hasStore' = IF DropOnHead /\ (head + 1) \notin secrets THEN FALSE ELSE hasStore
    /\ UNCHANGED <<epoch, removedAt, msgs, secrets, keeping, listed, gotRm>>

GetBox(m) ==
    /\ m \in msgs /\ m.t = "box"
    /\ msgs' = msgs \ {m}
    /\ secrets' = IF keeping THEN secrets \cup {m.e} ELSE secrets
    /\ UNCHANGED <<epoch, removedAt, reg, head, hasStore, keeping, listed, gotRm>>

GetRm(m) ==
    /\ m \in msgs /\ m.t = "rm"
    /\ msgs' = msgs \ {m}
    /\ keeping' = FALSE /\ hasStore' = FALSE /\ secrets' = {} /\ gotRm' = TRUE
    /\ UNCHANGED <<epoch, removedAt, reg, head, listed>>

Unlist ==
    /\ listed /\ listed' = FALSE
    /\ keeping' = FALSE /\ hasStore' = FALSE /\ secrets' = {}
    /\ UNCHANGED <<epoch, removedAt, msgs, reg, head, gotRm>>

Next == Rotate(TRUE) \/ Rotate(FALSE) \/ Register \/ Unlist
        \/ \E m \in msgs : GetBox(m) \/ GetRm(m)
Spec == Init /\ [][Next]_vars

Opens == keeping /\ IF OpenAny THEN secrets # {} ELSE head \in secrets
Stranded == keeping /\ head \notin secrets

\* §6 Stranded: K never drops data on a head move alone, only on its removal or an unlisting.
NoDropOnHeadMove == ~hasStore => (gotRm \/ ~listed)
\* §6: K removed opens S at no step past its removal.
RemovedStops == (removedAt # None /\ head >= removedAt) => ~Opens
\* a K not removed and boxed for its head opens S (stranded only while a box is on its way)
StrandedOnlyWaiting == Stranded => (\E m \in msgs : m.t = "box" /\ m.e = head) \/ (removedAt # None /\ head >= removedAt)
====
