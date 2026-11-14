---- MODULE NetKeep ----
(* A node K keeping S unread follows its own grant (spec/sync-judgement.md §6): it holds sync
   secrets by epoch from boxes sealed to it, keeps its store while its synced group lists the
   thing, opens S only by the sync key of its head's step, is stranded (keeping its store) when
   the head moves to a step whose secret it lacks, and drops S on its removal notice or when
   unlisted. A granter rotates (a new step per sync epoch, boxing K unless it removed K) and
   registers steps at K; boxes, notices and Registers arrive in any order. A removal notice
   carries a removal signature by the delete key of the newest step its sender records (the step
   before the removing rotation, or that rotation's own); K drops S only on one that verifies under
   the delete key it judges by (SigRule), judged at arrival and again at each head move while
   held. A forger holding no delete key of S sends a notice with no valid signature. The granter
   may re-grant K once after removing it (a box of its newest epoch, and every rotation after
   boxes K again); the removal's old notice may still reach K. A removal signature binds the
   newest sync epoch its sender boxed the recipient at, and K takes it only at or past every sync
   epoch it holds (BindEpoch). *)
EXTENDS Integers, FiniteSets

CONSTANTS
    MaxEp,          \* sync epochs after the first
    DropOnHead,     \* control: K drops its store on a head move to a step it holds no secret of
    OpenAny,        \* control: K opens S by any sync secret it holds, not its head's
    SigRule,        \* the steps whose delete key a removal signature may verify under: "head",
                    \* "held" (§6: a step from the newest whose sync secret K holds to the head),
                    \* "none" (control: no signature check)
    Regrant,        \* the granter may re-grant K once after removing it
    BindEpoch       \* a notice counts only when the epoch it binds is at or past every one K holds

VARIABLES
    epoch,      \* the granter's newest sync epoch
    removedAt,  \* the epoch whose rotation removed K (MaxEp + 1: none)
    regrantAt,  \* the epoch the granter re-granted K at (None: not re-granted)
    msgs,       \* in flight to K: [t |-> "box" | "rm", e |-> epoch, b |-> epoch the notice binds]
    reg,        \* steps registered by the granter but not yet taken at K (Register in flight)
    secrets,    \* K's sync secrets by epoch
    head,       \* K's head step (step n bears epoch n's sync key)
    hasStore,   \* K keeps a nonempty store of S
    keeping,    \* K keeps S
    listed,     \* K's synced group lists the thing
    held,       \* removal notices K holds that did not verify yet
    forged,     \* the forger sent its notice
    dropBy      \* what dropped K's store: "none", "rm" (a genuine notice), "forged", "unlist",
                \* "stale" (the removal's notice while K held a secret of its re-grant)
vars == <<epoch, removedAt, regrantAt, msgs, reg, secrets, head, hasStore, keeping, listed, held, forged, dropBy>>

None == MaxEp + 1

Init ==
    /\ epoch = 0 /\ removedAt = None /\ regrantAt = None
    /\ msgs = {} /\ reg = {}
    /\ secrets = {0} /\ head = 0
    /\ hasStore = TRUE /\ keeping = TRUE /\ listed = TRUE
    /\ held = {} /\ forged = FALSE /\ dropBy = "none"

\* the newest step at or below head hd whose sync secret K holds (-1: none)
NewestHeld(hd) == LET h == {x \in secrets : x <= hd} IN IF h = {} THEN -1 ELSE CHOOSE x \in h : \A y \in h : y <= x
\* a notice's signature verifies at K with head hd (a forged one, e = -1, never); held none at or
\* below the head, the head's alone
Sig(m, hd) ==
    CASE SigRule = "none" -> TRUE
      [] m.e < 0 -> FALSE
      [] SigRule = "head" \/ NewestHeld(hd) < 0 -> m.e = hd
      [] OTHER -> NewestHeld(hd) <= m.e /\ m.e <= hd
Verifies(m, hd) == Sig(m, hd) /\ (BindEpoch => \A x \in secrets : x <= m.b)
\* K drops S on notice m: removed by another, shredding its store
Stop(m) ==
    /\ keeping' = FALSE /\ hasStore' = FALSE /\ secrets' = {} /\ held' = {}
    /\ dropBy' = IF dropBy # "none" THEN dropBy
                 ELSE IF m.e < 0 THEN "forged"
                 ELSE IF regrantAt # None /\ \E x \in secrets : x >= regrantAt THEN "stale"
                 ELSE "rm"

\* the granter rotates: a new step; K boxed unless removed now or before (and not re-granted since).
\* A removal's notice is signed by the step before the rotation or by the rotation's own, and binds
\* the newest epoch K was boxed at (the current one: every rotation before boxed K).
Rotate(remove, sig) ==
    /\ epoch < MaxEp
    /\ remove => removedAt = None
    /\ sig \in {epoch, epoch + 1}
    /\ epoch' = epoch + 1
    /\ removedAt' = IF remove THEN epoch + 1 ELSE removedAt
    /\ msgs' = msgs \cup (IF remove THEN {[t |-> "rm", e |-> sig, b |-> epoch]}
                          ELSE IF removedAt = None \/ regrantAt # None THEN {[t |-> "box", e |-> epoch + 1, b |-> 0]} ELSE {})
    /\ reg' = reg \cup {epoch + 1}
    /\ UNCHANGED <<regrantAt, secrets, head, hasStore, keeping, listed, held, forged, dropBy>>

\* the granter re-grants K, once, after removing it: a box of its newest epoch (past the removal's)
Regive ==
    /\ Regrant /\ removedAt # None /\ regrantAt = None /\ epoch >= removedAt
    /\ regrantAt' = epoch
    /\ msgs' = msgs \cup {[t |-> "box", e |-> epoch, b |-> 0]}
    /\ UNCHANGED <<epoch, removedAt, reg, secrets, head, hasStore, keeping, listed, held, forged, dropBy>>

\* the forger's notice: no signature by a delete key of S
Forge ==
    /\ ~forged /\ forged' = TRUE
    /\ msgs' = msgs \cup {[t |-> "rm", e |-> -1, b |-> MaxEp]}
    /\ UNCHANGED <<epoch, removedAt, regrantAt, reg, secrets, head, hasStore, keeping, listed, held, dropBy>>

\* K takes a Register (it needs no open: relayable by any node): steps are taken in order (a step
\* whose prev is the head); the notices it holds are judged again at the new head.
Register ==
    /\ keeping /\ (head + 1) \in reg
    /\ head' = head + 1 /\ reg' = reg \ {head + 1}
    /\ IF \E m \in held : Verifies(m, head + 1)
       THEN Stop(CHOOSE m \in held : Verifies(m, head + 1))
       ELSE /\ hasStore' = IF DropOnHead /\ (head + 1) \notin secrets THEN FALSE ELSE hasStore
            /\ UNCHANGED <<secrets, keeping, held, dropBy>>
    /\ UNCHANGED <<epoch, removedAt, regrantAt, msgs, listed, forged>>

GetBox(m) ==
    /\ m \in msgs /\ m.t = "box"
    /\ msgs' = msgs \ {m}
    /\ secrets' = IF keeping THEN secrets \cup {m.e} ELSE secrets
    /\ UNCHANGED <<epoch, removedAt, regrantAt, reg, head, hasStore, keeping, listed, held, forged, dropBy>>

GetRm(m) ==
    /\ m \in msgs /\ m.t = "rm"
    /\ msgs' = msgs \ {m}
    /\ IF keeping /\ Verifies(m, head)
       THEN Stop(m)
       ELSE /\ held' = IF keeping THEN held \cup {m} ELSE held
            /\ UNCHANGED <<secrets, keeping, hasStore, dropBy>>
    /\ UNCHANGED <<epoch, removedAt, regrantAt, reg, head, listed, forged>>

Unlist ==
    /\ listed /\ listed' = FALSE
    /\ keeping' = FALSE /\ hasStore' = FALSE /\ secrets' = {} /\ held' = {}
    /\ dropBy' = IF dropBy = "none" THEN "unlist" ELSE dropBy
    /\ UNCHANGED <<epoch, removedAt, regrantAt, msgs, reg, head, forged>>

Next == \/ \E sig \in 0..MaxEp : Rotate(TRUE, sig) \/ Rotate(FALSE, sig)
        \/ Register \/ Unlist \/ Forge \/ Regive
        \/ \E m \in msgs : GetBox(m) \/ GetRm(m)
Spec == Init /\ [][Next]_vars

Opens == keeping /\ IF OpenAny THEN secrets # {} ELSE head \in secrets
Stranded == keeping /\ head \notin secrets

\* §6 Stranded: K never drops data on a head move alone, on a forged notice or on its old removal
\* once it holds its re-grant, only on its removal or an unlisting.
NoDropOnHeadMove == ~hasStore => dropBy \in {"rm", "unlist"}
\* K's head at a step its removal cut it from (past the removal, before any re-grant)
Cut == removedAt # None /\ head >= removedAt /\ (regrantAt = None \/ head < regrantAt)
\* §6: K removed opens S at no step past its removal, until re-granted.
RemovedStops == Cut => ~Opens
\* a K not removed and boxed for its head opens S (stranded only while a box is on its way)
StrandedOnlyWaiting == Stranded => (\E m \in msgs : m.t = "box" /\ m.e = head) \/ Cut
\* §6 Stops: a removed K whose notice and Registers have all arrived (no rotation to come) keeps S no more.
Settled == epoch = MaxEp /\ (~\E m \in msgs : m.t = "rm" /\ m.e >= 0) /\ (reg = {} \/ ~keeping)
RemovedDrops == (Settled /\ removedAt # None /\ regrantAt = None) => ~keeping
====
