---- MODULE NetKeep ----
(* A node K keeping S unread follows its own grant (spec/sync-judgement.md §6): it holds sync
   secrets by epoch from boxes sealed to it (never dropped: an old box taken again adds nothing),
   keeps S while a held secret derives its head's sync key, and at a head none derives drops its
   copy (keeping its path and record) and takes nothing. It shows (spec/sync-opens.md §4) its
   head's key when held, else the held secrets no step of its path bears (with no head, every
   one). A granter G holding every real epoch rotates (one step per sync epoch, boxing K unless it
   removed K), may re-grant K once after removing it (a box of its newest epoch, and every
   rotation after boxes K again), and registers its steps in order at K while K shows a key G
   holds. Boxes and Registers arrive in any order. Content of step e is what G stamps for a head
   at e; K pulls it while open. With NoHead, K starts granted before any step is registered with
   it, its first box on its way. With FakeBox, a hostile box gives K a secret of a self-made epoch
   no step bears. Unlist: the account unlists the thing (K leaves: its store and path shredded,
   its record kept) and may list it again. *)
EXTENDS Integers, FiniteSets

CONSTANTS
    MaxEp,          \* sync epochs after the first
    Regrant,        \* the granter may re-grant K once after removing it
    NoHead,         \* K starts with no head: no step registered, its first box on its way
    FakeBox,        \* a hostile box claims a self-made epoch
    KeepCopy,       \* control: K keeps its copy at a head past its keys
    ShowAll,        \* control: past its keys, K shows every held secret
    ShowNone,       \* control: past its keys, K shows nothing
    TakeAny,        \* control: K takes content at a head past its keys
    DropPath        \* control: at a head past its keys K shreds its path too (no head again)

VARIABLES
    epoch,      \* G's newest sync epoch (steps 0..epoch, step n bears epoch n's sync key)
    removedAt,  \* the epoch whose rotation removed K (None: not removed)
    regrantAt,  \* the epoch G re-granted K at (None: not re-granted)
    msgs,       \* boxes in flight to K (epochs)
    secrets,    \* K's sync record: its sync secrets by epoch
    head,       \* K's head step (-1: none)
    store,      \* the steps whose content K holds
    listed,     \* K's synced group lists the thing
    relisted,   \* the account listed it again once
    stops       \* times K dropped its copy at a head past its keys (bounded by MaxStops)
vars == <<epoch, removedAt, regrantAt, msgs, secrets, head, store, listed, relisted, stops>>

None == MaxEp + 1
Fake == MaxEp + 2
MaxStops == 2 * MaxEp + 3

Init ==
    /\ epoch = 0 /\ removedAt = None /\ regrantAt = None
    /\ msgs = IF NoHead THEN {0} ELSE {}
    /\ secrets = IF NoHead THEN {} ELSE {0}
    /\ head = IF NoHead THEN -1 ELSE 0
    /\ store = {} /\ listed = TRUE /\ relisted = FALSE /\ stops = 0

\* the epochs G boxed K at
Boxed == {e \in 0..epoch : (removedAt = None \/ e < removedAt) \/ (regrantAt # None /\ e >= regrantAt)}
AtKey == head >= 0 /\ head \in secrets
\* what K shows: its head's key, else the held secrets no step of its path (0..head) bears
Shown ==
    IF ~listed THEN {}
    ELSE IF AtKey THEN {head}
    ELSE IF head < 0 \/ ShowAll THEN secrets
    ELSE IF ShowNone THEN {}
    ELSE {x \in secrets : x > head}
\* S is open between K and G: K shows a key G holds (a real epoch)
Opens == Shown \cap (0..epoch) # {}
\* K holds and takes at its head
Takes == AtKey \/ TakeAny

\* K's head moves to step h (a Register, or with DropPath none): past its keys, its copy goes
MoveHead(h) ==
    IF h \in secrets \/ KeepCopy
    THEN /\ head' = h /\ store' = store /\ UNCHANGED stops
    ELSE /\ stops < MaxStops
         /\ stops' = stops + 1 /\ store' = {}
         /\ head' = IF DropPath THEN -1 ELSE h

\* G rotates: a new step; K boxed unless removed now or before (and not re-granted since).
Rotate(remove) ==
    /\ epoch < MaxEp
    /\ remove => removedAt = None
    /\ epoch' = epoch + 1
    /\ removedAt' = IF remove THEN epoch + 1 ELSE removedAt
    /\ msgs' = IF ~remove /\ (removedAt = None \/ regrantAt # None) THEN msgs \cup {epoch + 1} ELSE msgs
    /\ UNCHANGED <<regrantAt, secrets, head, store, listed, relisted, stops>>

\* G re-grants K, once, after removing it: a box of its newest epoch
Regive ==
    /\ Regrant /\ removedAt # None /\ regrantAt = None /\ epoch >= removedAt
    /\ regrantAt' = epoch
    /\ msgs' = msgs \cup {epoch}
    /\ UNCHANGED <<epoch, removedAt, secrets, head, store, listed, relisted, stops>>

\* K takes a box: its secret joins the record
GetBox(e) ==
    /\ e \in msgs
    /\ msgs' = msgs \ {e} /\ secrets' = secrets \cup {e}
    /\ UNCHANGED <<epoch, removedAt, regrantAt, head, store, listed, relisted, stops>>

\* a hostile box: a self-made epoch no step bears
GetFake ==
    /\ FakeBox /\ Fake \notin secrets
    /\ secrets' = secrets \cup {Fake}
    /\ UNCHANGED <<epoch, removedAt, regrantAt, msgs, head, store, listed, relisted, stops>>

\* G registers its next step at K (in order; genesis first with no head), S open
Register ==
    /\ Opens /\ head < epoch
    /\ MoveHead(head + 1)
    /\ UNCHANGED <<epoch, removedAt, regrantAt, msgs, secrets, listed, relisted>>

\* K pulls the content G stamps for its head
Pull ==
    /\ Opens /\ head >= 0 /\ Takes /\ head \notin store
    /\ store' = store \cup {head}
    /\ UNCHANGED <<epoch, removedAt, regrantAt, msgs, secrets, head, listed, relisted, stops>>

\* unlisted, K leaves (its own entries elsewhere): store and path shredded, record kept
Unlist ==
    /\ listed /\ listed' = FALSE /\ store' = {} /\ head' = -1
    /\ UNCHANGED <<epoch, removedAt, regrantAt, msgs, secrets, relisted, stops>>
Relist ==
    /\ ~listed /\ ~relisted /\ listed' = TRUE /\ relisted' = TRUE
    /\ UNCHANGED <<epoch, removedAt, regrantAt, msgs, secrets, head, store, stops>>

Next == \/ Rotate(TRUE) \/ Rotate(FALSE) \/ Regive \/ GetFake \/ Register \/ Pull \/ Unlist \/ Relist
        \/ \E e \in msgs : GetBox(e)
Spec == Init /\ [][Next]_vars

\* K holds content only of steps G boxed it at: never what a removal cut it from.
OnlyBoxedContent == store \subseteq Boxed
\* K removed (and not re-granted), its head past the removal: it holds nothing and opens S nowhere.
Cut == removedAt # None /\ regrantAt = None /\ head >= removedAt
RemovedHoldsNothing == Cut => store = {}
RemovedClosed == Cut => ~Opens
\* no loop: K drops its copy a bounded number of times (each needs its head to move forward)
FewStops == stops < MaxStops
\* quiet: no rotation, box or Register left to come, nothing K could pull
Quiet == epoch = MaxEp /\ msgs = {} /\ ~ENABLED Register /\ ~ENABLED Pull
\* boxed for the current epoch and listed, K keeps S at G's head with its content, once quiet
\* (a late box or a re-grant re-fetches)
Refetches == (Quiet /\ listed /\ epoch \in Boxed) => (head = epoch /\ epoch \in store)
====
