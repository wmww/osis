------------------------------- MODULE Rotation -------------------------------
(* Read-role rotation, departures, label registration steps, claims and       *)
(* re-seal for one actor whose label sits at one blind server (spec/crypto.md  *)
(* §4-§5, spec/sync.md §2 and §5, spec/permissions.md §3-§4).                  *)
(* Crypto is access: sec[x] is the set of epochs whose secret x holds; a box   *)
(* is membership of x in ep[e].boxes; a wrap is the epoch a blob is under.     *)
EXTENDS Naturals, FiniteSets, Sequences

CONSTANTS Admins,     \* may rotate, register, write content
          Readers,    \* read-only members
          Remover,    \* the admin that may remove
          Departing,  \* members it may remove
          MaxE,       \* epoch ids 0..MaxE (0 = the initial epoch)
          Writes,     \* content writes in a run
          DropClaims, \* TRUE: the server may drop superseded steps' claim sets
          Offs,       \* offline transitions in a run
          InOrder     \* TRUE: downloads follow the server's log order

Nodes == Admins \cup Readers
Ids == 0..MaxE
Max(S) == CHOOSE x \in S : \A y \in S : x >= y

VARIABLES ep,       \* ep[e] = [n, sup, boxes, ob, hist]; ob = boxes at rotation
          made,     \* created epoch ids
          kn,       \* kn[x]: rotation commits x holds (0 always)
          sec,      \* sec[x]: epoch secrets x holds
          dep,      \* dep[x]: departures x knows of
          removed,  \* departures that happened
          srvRot,   \* rotation commits at the server
          before,   \* before[k]: removals logged before rotation k's upload
          srvRem,   \* removal commits at the server: <<member, wrap epoch>>
          steps,    \* registration path: <<[ep, cl, dr]>>; dr = claim set dropped
          inbox,    \* re-seal boxes in flight: <<member, epoch>>
          stranded, \* members whose stranded heartbeat is under the label
          enc,      \* content written: <<epoch, departures the writer knew>>
          online, budget
vars == <<ep, made, kn, sec, dep, removed, srvRot, before, srvRem, steps, inbox,
          stranded, enc, online, budget>>

ep_n(e) == ep[e].n
\* crypto §4: newest = greatest n, ties by lowest nonce (here: lowest id).
Newer(e, f) == ep_n(e) > ep_n(f) \/ (ep_n(e) = ep_n(f) /\ e < f)
NewestOf(S) == CHOOSE e \in S : \A f \in S \ {e} : Newer(e, f)
\* crypto §4: current = no held rotation supersedes it.
Cur(x) == {e \in kn[x] : ~\E f \in kn[x] : e \in ep[f].sup}
HeldCur(x) == Cur(x) \cap sec[x]
\* crypto §5: an uploader wraps under the newest read epoch it holds.
EncEp(x) == NewestOf(IF HeldCur(x) # {} THEN HeldCur(x) ELSE sec[x])
\* crypto §4: an epoch covers a departure of M if it holds no box for M.
Covers(x, e) == \A m \in dep[x] : m \notin ep[e].boxes
\* crypto §5: a rotation commit is wrapped under the newest epoch it supersedes.
WrapOf(k) == NewestOf(ep[k].sup)
Top == steps[Len(steps)]
\* sync §5 re-registration: an admin holding an epoch newer than the head's
\* issues a child before any upload there.
NeedsReg(a) == Newer(EncEp(a), Top.ep)
\* sync §2/§5 open: a sync key of the head, or of the newest superseded step
\* bearing it, answered with its child; then claims at each later step (the
\* n round trips are one step here); a dropped claim set refuses the claim.
CanOpen(x) ==
  \E j \in 1..Len(steps) :
    /\ steps[j].ep \in sec[x]
    /\ \A k \in (j + 1)..Len(steps) :
         steps[k].ep \in sec[x] \/ (x \in steps[k].cl /\ ~steps[k].dr)

-----------------------------------------------------------------------------
Init ==
  /\ ep = [e \in Ids |-> IF e = 0
             THEN [n |-> 0, sup |-> {}, boxes |-> Nodes, ob |-> Nodes, hist |-> {}]
             ELSE [n |-> 0, sup |-> {}, boxes |-> {}, ob |-> {}, hist |-> {}]]
  /\ made = {0}
  /\ kn = [x \in Nodes |-> {0}]
  /\ sec = [x \in Nodes |-> {0}]
  /\ dep = [x \in Nodes |-> {}]
  /\ removed = {}
  /\ srvRot = {} /\ srvRem = {} /\ before = [k \in Ids |-> {}]
  /\ steps = <<[ep |-> 0, cl |-> Nodes, dr |-> FALSE]>>
  /\ inbox = {} /\ stranded = {}
  /\ enc = {}
  /\ online = [x \in Nodes |-> TRUE]
  /\ budget = [w |-> 0, off |-> 0]

\* permissions §3 / crypto §4: fresh epoch n+1 superseding the current ones
\* the rotator holds, boxed to every current member it knows, history box of
\* every secret it holds.
Rotate(a) ==
  /\ online[a] /\ Cardinality(made) <= MaxE
  /\ LET k == Cardinality(made)
         sup == Cur(a)
     IN /\ ep' = [ep EXCEPT ![k] = [n |-> 1 + Max({ep[e].n : e \in sup}),
                    sup |-> sup, boxes |-> Nodes \ dep[a], ob |-> Nodes \ dep[a],
                    hist |-> sec[a]]]
        /\ made' = made \cup {k}
        /\ kn' = [kn EXCEPT ![a] = @ \cup {k}]
        /\ sec' = [sec EXCEPT ![a] = @ \cup {k}]
  /\ UNCHANGED <<dep, removed, srvRot, before, srvRem, steps, inbox, stranded, enc, online, budget>>
\* permissions §3: MUST rotate before encrypting under a secret it would
\* replace (a write is pending while the budget lasts); MAY rotate eagerly.
RotateForced(a) == budget.w < Writes /\ ~Covers(a, EncEp(a)) /\ Rotate(a)

Register(a) ==
  /\ online[a] /\ NeedsReg(a)
  /\ steps' = Append(steps, [ep |-> EncEp(a), cl |-> ep[EncEp(a)].boxes, dr |-> FALSE])
  /\ UNCHANGED <<ep, made, kn, sec, dep, removed, srvRot, before, srvRem, inbox, stranded, enc, online, budget>>

UploadRot(a, k) ==
  /\ online[a] /\ k \in kn[a] \ srvRot /\ k # 0 /\ ~NeedsReg(a)
  /\ srvRot' = srvRot \cup {k}
  /\ before' = [before EXCEPT ![k] = srvRem]
  /\ UNCHANGED <<ep, made, kn, sec, dep, removed, srvRem, steps, inbox, stranded, enc, online, budget>>

\* permissions §3: the remover places the removal in the same sync, before
\* any other upload.
Remove(m) ==
  /\ online[Remover] /\ m \in Departing \ removed /\ ~NeedsReg(Remover)
  /\ removed' = removed \cup {m}
  /\ dep' = [dep EXCEPT ![Remover] = @ \cup {m}]
  /\ srvRem' = srvRem \cup {<<m, EncEp(Remover)>>}
  /\ UNCHANGED <<ep, made, kn, sec, srvRot, before, steps, inbox, stranded, enc, online, budget>>

\* crypto §4: never encrypt under an epoch that does not cover a known departure.
WriteContent(a) ==
  /\ online[a] /\ budget.w < Writes /\ ~NeedsReg(a) /\ Covers(a, EncEp(a))
  /\ enc' = enc \cup {<<EncEp(a), dep[a]>>}
  /\ budget' = [budget EXCEPT !.w = @ + 1]
  /\ UNCHANGED <<ep, made, kn, sec, dep, removed, srvRot, before, srvRem, steps, inbox, stranded, online>>

\* Download of a rotation commit: readable under its wrap epoch; a box for x
\* gives the new secret and, by the history box, every secret the rotator held.
\* InOrder: the server's log order is kept (cursor sync); otherwise any order
\* (range reconciliation, other servers, a reordering server).
CanRecv(x, k) == /\ online[x] /\ CanOpen(x) /\ k \in srvRot \ kn[x] /\ WrapOf(k) \in sec[x]
                 /\ InOrder => \A r \in before[k] : r[2] \in sec[x] => r[1] \in dep[x]
Recv(x, k) ==
  /\ CanRecv(x, k)
  /\ kn' = [kn EXCEPT ![x] = @ \cup {k}]
  /\ sec' = [sec EXCEPT ![x] = @ \cup (IF x \in ep[k].boxes THEN {k} \cup ep[k].hist ELSE {})]
  /\ UNCHANGED <<ep, made, dep, removed, srvRot, before, srvRem, steps, inbox, stranded, enc, online, budget>>

RecvRem(x, r) ==
  /\ online[x] /\ CanOpen(x) /\ r \in srvRem /\ r[1] \notin dep[x] /\ r[2] \in sec[x]
  /\ dep' = [dep EXCEPT ![x] = @ \cup {r[1]}]
  /\ UNCHANGED <<ep, made, kn, sec, removed, srvRot, before, srvRem, steps, inbox, stranded, enc, online, budget>>

\* permissions §3: SHOULD re-seal a current member seen without a box at a
\* current epoch, or whose heartbeat reports it stranded; by inbox.
Reseal(a, m) ==
  /\ online[a] /\ m \notin dep[a] /\ m # a
  /\ LET miss == {e \in HeldCur(a) : m \notin ep[e].boxes}
         E == IF miss # {} THEN miss ELSE HeldCur(a)
     IN /\ miss # {} \/ m \in stranded
        /\ ep' = [e \in Ids |-> IF e \in E THEN [ep[e] EXCEPT !.boxes = @ \cup {m}] ELSE ep[e]]
        /\ inbox' = inbox \cup {<<m, e>> : e \in E}
        /\ stranded' = stranded \ {m}
  /\ UNCHANGED <<made, kn, sec, dep, removed, srvRot, before, srvRem, steps, enc, online, budget>>

\* The re-seal box gives the secret; the history box stays in the rotation
\* commit, which is wrapped under the epoch before (AMBIGUITIES.md).
InboxRecv(m, e) ==
  /\ online[m] /\ <<m, e>> \in inbox
  /\ sec' = [sec EXCEPT ![m] = @ \cup {e}]
  /\ inbox' = inbox \ {<<m, e>>}
  /\ UNCHANGED <<ep, made, kn, dep, removed, srvRot, before, srvRem, steps, stranded, enc, online, budget>>

\* permissions §4: MUST place a stranded heartbeat when it reached the head
\* but cannot open the epoch it registers (deposit: no open needed to place).
Heartbeat(x) ==
  /\ online[x] /\ CanOpen(x) /\ Top.ep \notin sec[x] /\ x \notin stranded
  /\ ~\E k \in srvRot : CanRecv(x, k)
  /\ stranded' = stranded \cup {x}
  /\ UNCHANGED <<ep, made, kn, sec, dep, removed, srvRot, before, srvRem, steps, inbox, enc, online, budget>>

\* sync §4: a superseded step's claim set is kept MEMBERSHIP_KEEP, then may go.
Drop(i) ==
  /\ DropClaims /\ i < Len(steps) /\ ~steps[i].dr
  /\ steps' = [steps EXCEPT ![i].dr = TRUE]
  /\ UNCHANGED <<ep, made, kn, sec, dep, removed, srvRot, before, srvRem, inbox, stranded, enc, online, budget>>

GoOff(x) == /\ online[x] /\ budget.off < Offs
            /\ online' = [online EXCEPT ![x] = FALSE] /\ budget' = [budget EXCEPT !.off = @ + 1]
            /\ UNCHANGED <<ep, made, kn, sec, dep, removed, srvRot, before, srvRem, steps, inbox, stranded, enc>>
GoOn(x) == /\ ~online[x] /\ online' = [online EXCEPT ![x] = TRUE]
           /\ UNCHANGED <<ep, made, kn, sec, dep, removed, srvRot, before, srvRem, steps, inbox, stranded, enc, budget>>

Next ==
  \/ \E a \in Admins : Rotate(a) \/ Register(a) \/ WriteContent(a)
                       \/ (\E k \in Ids : UploadRot(a, k))
                       \/ (\E m \in Nodes : Reseal(a, m))
  \/ \E m \in Departing : Remove(m)
  \/ \E x \in Nodes : \/ Heartbeat(x) \/ GoOff(x) \/ GoOn(x)
                      \/ (\E k \in Ids : Recv(x, k) \/ InboxRecv(x, k))
                      \/ (\E r \in srvRem : RecvRem(x, r))
  \/ \E i \in 1..Len(steps) : Drop(i)

\* Weak fairness of honest steps; eager rotation, removal, writes, claim-set
\* drops and going offline are unfair.
Fairness ==
  /\ \A a \in Admins : /\ WF_vars(RotateForced(a)) /\ WF_vars(Register(a))
                       /\ \A k \in Ids : WF_vars(UploadRot(a, k))
                       /\ \A m \in Nodes : WF_vars(Reseal(a, m))
  /\ \A x \in Nodes : /\ WF_vars(Heartbeat(x)) /\ WF_vars(GoOn(x))
                      /\ \A k \in Ids : WF_vars(Recv(x, k)) /\ WF_vars(InboxRecv(x, k))
                      /\ WF_vars(\E r \in srvRem : RecvRem(x, r))

Spec == Init /\ [][Next]_vars /\ Fairness

-----------------------------------------------------------------------------
GCur == {e \in made : ~\E f \in made : e \in ep[f].sup}

TypeOK == /\ made \subseteq Ids /\ removed \subseteq Departing
          /\ \A x \in Nodes : sec[x] \subseteq made /\ kn[x] \subseteq made

\* crypto §4 covers rule, its purpose: content a writer encrypted while it
\* knew of M's departure is never readable by M.
NoLeak == \A c \in enc : \A m \in c[2] : c[1] \notin sec[m]
\* permissions §3 "requires rotating every role secret M could open": a
\* departed member never holds an epoch whose rotation did not box it.
DepartedLocked == \A m \in removed : \A e \in sec[m] : m \in ep[e].ob

\* permissions §3 / sync §5: every current member eventually opens every
\* current epoch (by claims, downloads or re-seal) ...
CurrentOpens == <>[](\A x \in Nodes \ removed : GCur \subseteq sec[x])
\* ... and reads the label: every epoch content was written under.
ReadsAll == <>[](\A x \in Nodes \ removed : \A c \in enc : c[1] \in sec[x])
=============================================================================
