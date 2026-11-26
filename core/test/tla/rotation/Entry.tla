-------------------------------- MODULE Entry --------------------------------
(* How a holder that cannot open X's newest rotation by its wrap gets X's  *)
(* current secrets (notes/stub-rewrite.md Q1, Q2): entry boxes in X's steps*)
(* or commits sealed to it as notices, nothing kept with the holder. One X, *)
(* one admin (it rotates, removes, issues steps and registers them),       *)
(* holders H: readers                                                     *)
(* and sync-only holders. Read and sync rotate together: epoch k gives the  *)
(* read secret (readers) and the sync secret (both) of step epochs k.       *)
(* Rotation k is wrapped under epoch k-1 and boxes every holder the admin   *)
(* knows current; a sync-only holder opens no rotation (it holds no read    *)
(* secret). A step registers an epoch and carries its claim set: readers    *)
(* listed by claim key (holders of boxes at its epoch), claim-keyed entry   *)
(* boxes (found by a holder that holds the step with its claim set), and    *)
(* static entries (a credential the holder holds as a value, so it finds    *)
(* the head's box knowing no step: Behind naming none, spec/sync-ids.md §6).*)
(* An entry box at step j gives j's epoch (and, to a reader, the epoch it   *)
(* supersedes).                                                             *)
(* Readers walk (spec/sync-ids.md §6 Walk): open S at the head by a         *)
(* credential of it (its sync key, a claim at a known step, a static entry  *)
(* listed there) and pull the rotations; Behind by a credential of a known  *)
(* step gives the steps through the first under another sync key. A        *)
(* superseded step's claim set may be dropped (ROLE_KEEP): it gives no      *)
(* claim and its claim-keyed boxes are gone. Sync-only holders keep S       *)
(* unread: a reader registers the steps past the store's head with their    *)
(* claim sets (to a store it judges departed, only the first past its       *)
(* keys); the store stops while its head's sync key is one it lacks.        *)
(* Holders the admin learns late (Hidden: granted at start beside the admin's*)
(* knowledge; Late: granted later by a granter) are left out of rotations   *)
(* until it learns them. A signalled grant (Sig) gives the holder a static  *)
(* entry's seed as a value; the entry stands while the signal does.         *)
(* Rules:                                                                   *)
(*   Reseal   "request": a stranded reader generates a static entry and     *)
(*            sends its public half with its Stranded message; the entry    *)
(*            stands in every step until its lifetime ends (Lapse), and the *)
(*            reader requests again while still stranded;                   *)
(*            "next": a left-out reader learned by the admin gets a         *)
(*            claim-keyed box in X's next step (Q2(a) as written).         *)
(*   SyncBox  "every": every step boxes every current sync-only holder      *)
(*            (claim-keyed, as the public's box where it holds sync alone);*)
(*            "next": only a step bearing a new sync key does (Q2(a) as    *)
(*            written); under "notice", "next" seals a rotation to no      *)
(*            sync-only holder it boxed before (control).                   *)
(*   SigEntry "stand": a signal's entry is in every step while the signal  *)
(*            stands; "once": in one step only (control).                  *)
(*   Judge    TRUE: entries and boxes only for holders the admin judges    *)
(*            current; FALSE: for any seed holder, and "notice" sealing   *)
(*            to a removed holder (controls).                              *)
(*   Deliver  "entry": all of the above lives in X's steps;               *)
(*            "notice": nothing in the steps; each role commit boxing a    *)
(*            holder that cannot open its wrap (a grant, a re-seal, a      *)
(*            rotation to a sync-only holder or to a reader holding no box *)
(*            at the epoch it is wrapped under) also seals its blob key to *)
(*            that holder, as a notice does, under X's sync ID; a reader   *)
(*            opening S toward the holder by its role (ByRole, judged on   *)
(*            X's roster) serves it; "copies": the deleted design, those   *)
(*            boxes as sealed copies under the holder (control).           *)
(* Properties: Live (no current holder that has entered stops for good: it  *)
(* holds the current epoch and, sync-only, its store stands at the head);  *)
(* SigLive (a signalled holder enters while its signal stands); NoGain (a  *)
(* removed holder holds no epoch made at or after its removal);            *)
(* NothingKept (nothing is kept outside X's own data); StepsBare (a step  *)
(* carries no per-holder box: a store keeping X unread sees only padded    *)
(* claim sets, never a count of holders or grants).                        *)
EXTENDS Naturals, FiniteSets, Sequences

CONSTANTS Readers, SyncOnly, Start, Hidden, Late, Sig, Rem,
          MaxE, MaxIdle, MaxLapse, CanDrop,
          Reseal, SyncBox, SigEntry, Judge, Deliver

H == Readers \cup SyncOnly
ASSUME Readers \cap SyncOnly = {} /\ Sig \subseteq Late /\ Rem \subseteq H
ASSUME Start \cap Hidden = {} /\ Start \cap Late = {} /\ Hidden \cap Late = {}

VARIABLES e,       \* the current epoch
          rb,      \* rb[k]: holders rotation k boxes
          bx,      \* bx[k]: holders holding a box at epoch k (claims list them)
          steps,   \* <<[e, lst, cb, st]>>
          drop,    \* superseded steps whose claim sets are dropped
          granted, known, gone, remEp,
          sec,     \* sec[h]: epochs h holds
          kst,     \* kst[h]: newest step a reader knows (0: none)
          head,    \* head[h]: a sync-only holder's store head (0: none)
          sig,     \* sig[h]: h holds a standing signal's entry seed
          req,     \* req[h]: h's stranded request's entry stands
          sigOnce, \* SigEntry "once": signals already listed
          rsp,     \* Reseal "next": re-seals waiting for the next step
          sealed,  \* <<h, k>>: a box of epoch k sealed to h ("copies": under h's
                   \* sync ID; "notice": under X's)
          cnt      \* [idle, lapse]
vars == <<e, rb, bx, steps, drop, granted, known, gone, remEp, sec, kst, head,
          sig, req, sigOnce, rsp, sealed, cnt>>

Top == Len(steps)
Ep(j) == steps[j].e
Cur(h) == h \in granted \ gone
AdmCur == known \ gone
Seed(h) == sig[h] \/ req[h]
Max(S) == CHOOSE x \in S : \A y \in S : x >= y

\* static entries the admin lists in a new step
StEnt ==
  {h \in H : /\ Deliver # "notice"
             /\ \/ req[h]
                \/ (sig[h] /\ h \in known /\ (SigEntry = "once" => h \notin sigOnce))
             /\ Judge => h \in AdmCur}
\* claim-keyed boxes in a new step at epoch k (fresh: a new sync key)
CB(fresh) ==
  IF Deliver # "entry" THEN {}
  ELSE (IF SyncBox = "every" \/ fresh THEN SyncOnly \cap AdmCur ELSE {})
       \cup (IF Reseal = "next" THEN rsp ELSE {})
NewStep(k, fresh) ==
  [e |-> k, lst |-> Readers \cap bx[k] \cap AdmCur, cb |-> CB(fresh), st |-> StEnt]
\* what an entry box at step j gives h
Gives(j, h) == IF h \in Readers /\ Ep(j) > 1 THEN {Ep(j), Ep(j) - 1} ELSE {Ep(j)}
\* rotations h opens from what it holds (readers only)
RECURSIVE Clo(_, _)
Clo(S, h) == LET T == S \cup {k \in 2..e : k - 1 \in S /\ h \in rb[k]}
             IN IF T = S THEN S ELSE Clo(T, h)
SetHeld(j) == j = Top \/ j \notin drop

Init ==
  /\ e = 1
  /\ rb = [k \in 1..MaxE |-> {}]
  /\ bx = [k \in 1..MaxE |-> IF k = 1 THEN Start \cup Hidden ELSE {}]
  /\ granted = Start \cup Hidden /\ known = Start /\ gone = {}
  /\ remEp = [h \in H |-> 0]
  /\ sig = [h \in H |-> FALSE] /\ req = [h \in H |-> FALSE]
  /\ sigOnce = {} /\ rsp = {} /\ sealed = {}
  /\ steps = <<[e |-> 1, lst |-> Readers \cap Start,
                cb |-> IF Deliver # "entry" THEN {} ELSE SyncOnly \cap Start, st |-> {}]>>
  /\ drop = {}
  /\ sec = [h \in H |-> IF h \in Start \cup Hidden THEN {1} ELSE {}]
  /\ kst = [h \in H |-> IF h \in Readers /\ h \in Start \cup Hidden THEN 1 ELSE 0]
  /\ head = [h \in H |-> IF h \in SyncOnly /\ h \in Start \cup Hidden THEN 1 ELSE 0]
  /\ cnt = [idle |-> 0, lapse |-> 0]

\* the admin issues a step (rotating or not)
Issue(k, fresh) ==
  /\ steps' = Append(steps, NewStep(k, fresh))
  /\ drop' = drop
  /\ sigOnce' = IF SigEntry = "once" THEN sigOnce \cup {h \in StEnt : sig[h]} ELSE sigOnce
  /\ rsp' = {}

RotateR(R) ==
  /\ e < MaxE
  /\ e' = e + 1
  /\ gone' = gone \cup R
  /\ rb' = [rb EXCEPT ![e + 1] = known \ (gone \cup R)]
  /\ bx' = [bx EXCEPT ![e + 1] = known \ (gone \cup R)]
  /\ remEp' = [h \in H |-> IF h \in R THEN e + 1 ELSE remEp[h]]
  /\ sealed' = CASE Deliver = "copies" -> sealed \cup {<<s, e + 1>> : s \in SyncOnly \cap (known \ (gone \cup R))}
               [] Deliver = "notice" -> sealed \cup {<<h, e + 1>> : h \in (IF Judge THEN known \ (gone \cup R) ELSE known)
                                                                \cap ((IF SyncBox = "every" THEN SyncOnly ELSE {}) \cup (H \ bx[e]))}
               [] OTHER -> sealed
  /\ steps' = Append(steps, [NewStep(e + 1, TRUE) EXCEPT
                !.lst = Readers \cap (known \ (gone \cup R)),
                !.cb = IF Deliver # "entry" THEN {}
                       ELSE (SyncOnly \cap (known \ (gone \cup R))) \cup (IF Reseal = "next" THEN rsp ELSE {}),
                !.st = {h \in StEnt : Judge => h \notin R}])
  /\ drop' = drop
  /\ sigOnce' = IF SigEntry = "once" THEN sigOnce \cup {h \in StEnt : sig[h]} ELSE sigOnce
  /\ rsp' = {}
  /\ UNCHANGED <<granted, known, sec, kst, head, sig, req, cnt>>

Rotate == RotateR({})
Remove(x) == x \in Rem /\ Cur(x) /\ RotateR({x})

\* a step without a rotation (to list link keys, say): bounded
Idle ==
  /\ cnt.idle < MaxIdle
  /\ Issue(e, FALSE)
  /\ cnt' = [cnt EXCEPT !.idle = @ + 1]
  /\ UNCHANGED <<e, rb, bx, granted, known, gone, remEp, sec, kst, head, sig, req, sealed>>

\* a step due because an entry or box the admin owes is not on the head
Pending ==
  \/ StEnt \ steps[Top].st # {}
  \/ CB(FALSE) \ steps[Top].cb # {}
EntryStep ==
  /\ Pending
  /\ Issue(e, FALSE)
  /\ UNCHANGED <<e, rb, bx, granted, known, gone, remEp, sec, kst, head, sig, req, sealed, cnt>>

Drop(j) ==
  /\ CanDrop /\ j < Top /\ j \notin drop
  /\ drop' = drop \cup {j}
  /\ UNCHANGED <<e, rb, bx, steps, granted, known, gone, remEp, sec, kst, head, sig, req,
                 sigOnce, rsp, sealed, cnt>>

\* a granter (not the admin) grants h at the current epoch, signalled or not
Grant(h) ==
  /\ h \in Late \ granted
  /\ granted' = granted \cup {h}
  /\ bx' = [bx EXCEPT ![e] = @ \cup {h}]
  /\ sig' = [sig EXCEPT ![h] = h \in Sig]
  /\ sealed' = IF Deliver = "notice" THEN sealed \cup {<<h, e>>} ELSE sealed
  /\ UNCHANGED <<e, rb, steps, drop, known, gone, remEp, sec, kst, head, req, sigOnce, rsp,
                 cnt>>

\* the admin learns a grant from X's role entries; under "next" it re-seals a
\* holder holding no box at the current epoch
Learn(h) ==
  /\ h \in granted \ known
  /\ known' = known \cup {h}
  /\ LET out == h \notin bx[e] /\ Cur(h)
     IN /\ rsp' = IF Reseal = "next" /\ Deliver = "entry" /\ out /\ h \in Readers THEN rsp \cup {h} ELSE rsp
        /\ bx' = IF out /\ (Reseal = "next" \/ Deliver # "entry") THEN [bx EXCEPT ![e] = @ \cup {h}] ELSE bx
        /\ sealed' = IF Deliver # "entry" /\ out THEN sealed \cup {<<h, e>>} ELSE sealed
  /\ UNCHANGED <<e, rb, steps, drop, granted, gone, remEp, sec, kst, head, sig, req, sigOnce, cnt>>

Expire(h) ==
  /\ sig[h]
  /\ sig' = [sig EXCEPT ![h] = FALSE]
  /\ UNCHANGED <<e, rb, bx, steps, drop, granted, known, gone, remEp, sec, kst, head, req,
                 sigOnce, rsp, sealed, cnt>>

\* readers: a credential of step j
Cred(h, j) ==
  \/ Ep(j) \in sec[h]
  \/ (h \in steps[j].lst /\ kst[h] >= j /\ SetHeld(j))
  \/ (Seed(h) /\ h \in steps[j].st)
BoxAt(h, j) == (h \in steps[j].cb /\ SetHeld(j)) \/ (Seed(h) /\ h \in steps[j].st)

\* open S at the head and pull: the head's box, then the rotations
Open(h) ==
  /\ h \in Readers /\ Cred(h, Top)
  /\ LET s == Clo(sec[h] \cup (IF BoxAt(h, Top) THEN Gives(Top, h) ELSE {}), h)
     IN /\ s # sec[h] \/ kst[h] # Top
        /\ sec' = [sec EXCEPT ![h] = s]
        /\ kst' = [kst EXCEPT ![h] = Top]
  /\ UNCHANGED <<e, rb, bx, steps, drop, granted, known, gone, remEp, head, sig, req, sigOnce,
                 rsp, sealed, cnt>>

\* Behind by the newest known step it holds a credential of
NextKey(i) == IF \E j \in i + 1..Top : Ep(j) # Ep(i)
              THEN CHOOSE j \in i + 1..Top : Ep(j) # Ep(i) /\ \A m \in i + 1..j - 1 : Ep(m) = Ep(i)
              ELSE Top
CredSteps(h) == {j \in 1..kst[h] : Cred(h, j)}
BehindTo(h) == IF CredSteps(h) = {} THEN 0 ELSE NextKey(Max(CredSteps(h)))
Behind(h) ==
  /\ h \in Readers /\ kst[h] >= 1 /\ BehindTo(h) > kst[h]
  /\ kst' = [kst EXCEPT ![h] = BehindTo(h)]
  /\ UNCHANGED <<e, rb, bx, steps, drop, granted, known, gone, remEp, sec, head, sig, req,
                 sigOnce, rsp, sealed, cnt>>

\* stranded: entered, and no credential or Behind moves it
Stranded(h) == h \in Readers /\ sec[h] # {} /\ ~Cred(h, Top) /\ BehindTo(h) <= kst[h]
Request(h) ==
  /\ Reseal = "request" /\ Deliver # "notice" /\ Stranded(h) /\ ~req[h]
  /\ req' = [req EXCEPT ![h] = TRUE]
  /\ UNCHANGED <<e, rb, bx, steps, drop, granted, known, gone, remEp, sec, kst, head, sig,
                 sigOnce, rsp, sealed, cnt>>
Lapse(h) ==
  /\ req[h] /\ cnt.lapse < MaxLapse
  /\ req' = [req EXCEPT ![h] = FALSE]
  /\ cnt' = [cnt EXCEPT !.lapse = @ + 1]
  /\ UNCHANGED <<e, rb, bx, steps, drop, granted, known, gone, remEp, sec, kst, head, sig,
                 sigOnce, rsp, sealed>>

\* sync-only: a reader registers the steps past the store's head (to one it
\* judges departed, only through the first past its keys)
RegTo(s) == IF s \in AdmCur THEN Top
            ELSE IF \E j \in head[s] + 1..Top : Ep(j) \notin sec[s]
                 THEN CHOOSE j \in head[s] + 1..Top : Ep(j) \notin sec[s] /\ \A m \in head[s] + 1..j - 1 : Ep(m) \in sec[s]
                 ELSE Top
Reg(s) ==
  /\ s \in SyncOnly /\ head[s] >= 1 /\ head[s] < Top
  /\ head' = [head EXCEPT ![s] = RegTo(s)]
  /\ sec' = [sec EXCEPT ![s] = @ \cup {Ep(j) : j \in {m \in head[s] + 1..RegTo(s) : BoxAt(s, m)}}]
  /\ UNCHANGED <<e, rb, bx, steps, drop, granted, known, gone, remEp, kst, sig, req, sigOnce,
                 rsp, sealed, cnt>>
\* a sync-only holder's first entry by a static entry: the head's box and path
EnterS(s) ==
  /\ s \in SyncOnly /\ Seed(s) /\ s \in steps[Top].st /\ head[s] # Top
  /\ head' = [head EXCEPT ![s] = Top]
  /\ sec' = [sec EXCEPT ![s] = @ \cup Gives(Top, s)]
  /\ UNCHANGED <<e, rb, bx, steps, drop, granted, known, gone, remEp, kst, sig, req, sigOnce,
                 rsp, sealed, cnt>>
Entered(h) == sec[h] # {}
Stopped(s) == head[s] >= 1 /\ Ep(head[s]) \notin sec[s]

\* take the boxes sealed to h: "copies" from h's own sync ID, any time;
\* "notice" by a reader opening S toward h by its role (it judges h current
\* on X's roster; h knows X: it entered, or holds the signal), which also
\* registers its path at a sync-only store
Mine(h) == {c[2] : c \in {d \in sealed : d[1] = h}}
NewSec(h) == IF h \in Readers THEN Clo(sec[h] \cup Mine(h), h) ELSE sec[h] \cup Mine(h)
Take(h) ==
  /\ Deliver # "entry"
  /\ Deliver = "notice" => /\ (h \in AdmCur \/ (~Judge /\ h \in granted))
                          /\ (Entered(h) \/ sig[h])
  /\ \/ NewSec(h) # sec[h]
     \/ (Deliver = "notice" /\ h \in Readers /\ kst[h] # Top)
     \/ (Deliver = "notice" /\ h \in SyncOnly /\ head[h] # Top)
  /\ sec' = [sec EXCEPT ![h] = NewSec(h)]
  /\ kst' = IF Deliver = "notice" /\ h \in Readers THEN [kst EXCEPT ![h] = Top] ELSE kst
  /\ head' = IF Deliver = "notice" /\ h \in SyncOnly THEN [head EXCEPT ![h] = Top] ELSE head
  /\ UNCHANGED <<e, rb, bx, steps, drop, granted, known, gone, remEp, sig, req,
                 sigOnce, rsp, sealed, cnt>>

Next ==
  \/ Rotate \/ Idle \/ EntryStep
  \/ \E x \in H : Remove(x)
  \/ \E j \in 1..8 : Drop(j)
  \/ \E h \in H : Grant(h) \/ Learn(h) \/ Expire(h) \/ Open(h) \/ Behind(h) \/ Request(h)
                  \/ Lapse(h) \/ Reg(h) \/ EnterS(h) \/ Take(h)

Fair ==
  /\ WF_vars(EntryStep)
  /\ \A h \in H : /\ WF_vars(Learn(h)) /\ WF_vars(Open(h)) /\ WF_vars(Behind(h))
                  /\ WF_vars(Request(h)) /\ WF_vars(Reg(h)) /\ WF_vars(EnterS(h))
                  /\ WF_vars(Take(h))

Spec == Init /\ [][Next]_vars /\ Fair

Up(h) == e \in sec[h] /\ (h \in SyncOnly => head[h] = Top)
Live == \A h \in H : <>[](~(Cur(h) /\ Entered(h)) \/ Up(h))
SigLive == \A h \in Sig : (<>[] sig[h]) => <>[](~Cur(h) \/ Up(h))
NoGain == \A x \in gone : \A k \in sec[x] : k < remEp[x]
NothingKept == Deliver = "copies" => sealed = {}
StepsBare == \A j \in 1..Top : steps[j].cb = {} /\ steps[j].st = {}
=============================================================================
