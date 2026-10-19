------------------------------- MODULE Rotation -------------------------------
(* Read-role rotation, removals, grants, label registration steps, claims and *)
(* re-seal for one actor whose label sits at one blind server (spec/crypto.md  *)
(* §3-§5, spec/sync.md §2 and §5, spec/permissions.md §3-§4, commits §2).      *)
(* Crypto is access: sec[x] is the set of epochs whose secret x holds; a box   *)
(* is membership of x in ep[e].boxes; a wrap is the epoch a blob is under.     *)
EXTENDS Naturals, FiniteSets, Sequences

CONSTANTS Admins,     \* may rotate, register, grant, write content
          Readers,    \* read-only members
          Late,       \* members granted later (not boxed at epoch 0)
          Remover,    \* the admin that may remove
          Departing,  \* members it may remove
          MaxE,       \* epoch ids 0..MaxE (0 = the initial epoch)
          Writes,     \* content writes in a run
          DropClaims, \* TRUE: the server may drop superseded steps' claim sets
          Refresh,    \* TRUE: every rotation refreshes the deposit seed (a MAY)
          Offs,       \* offline transitions in a run
          InOrder     \* TRUE: one source, the server's log order (cursor sync);
                      \* FALSE: any order, and member peers serve rotations

Nodes == Admins \cup Readers
Ids == 0..MaxE
Max(S) == CHOOSE x \in S : \A y \in S : x >= y

VARIABLES ep,       \* ep[e] = [n, sup, boxes, ob, hist, rem]; ob = boxes at
                    \* rotation; rem = removals the rotation commit carries
          made,     \* created epoch ids
          kn,       \* kn[x]: rotation commits x holds (0 always)
          sec,      \* sec[x]: epoch secrets x holds
          dep,      \* dep[x]: departures x knows of
          mem,      \* mem[x]: members x knows were granted
          removed,  \* departures that happened
          granted,  \* Late members granted so far
          srvRot,   \* rotation commits at the server
          before,   \* before[k]: rotations logged before rotation k's upload
          srvGrant, \* grant commits at the server: <<grantee, wrap epoch>>
          steps,    \* registration path: <<[ep, cl, dr]>>; dr = claim set dropped
          inbox,    \* grant and re-seal boxes in flight: <<member, epoch>>
          via,      \* via[x]: member peers x received rotation commits from
          stranded, \* members whose stranded heartbeat is under the label
          enc,      \* content written: <<epoch, departures the writer knew>>
          online, budget
vars == <<ep, made, kn, sec, dep, mem, removed, granted, srvRot, before, srvGrant,
          steps, inbox, via, stranded, enc, online, budget>>

ep_n(e) == ep[e].n
\* crypto §4: newest = greatest n, ties by lowest nonce (here: lowest id).
Newer(e, f) == ep_n(e) > ep_n(f) \/ (ep_n(e) = ep_n(f) /\ e < f)
NewestOf(S) == CHOOSE e \in S : \A f \in S \ {e} : Newer(e, f)
\* crypto §4: an epoch is established at x when it is x's own rotation, or x
\* applied its rotation commit and every epoch it supersedes is established
\* (own rotations are in kn at once and supersede established epochs only).
\* Epoch 0 is the derived epoch. No /secrets snapshots (ASSUMPTIONS.md). A
\* rotation supersedes lower ids only, so one pass in id order is the fixpoint.
Est(x) == LET f[i \in Ids] == IF i = 0 THEN TRUE
                              ELSE i \in kn[x] /\ \A j \in ep[i].sup : j < i /\ f[j]
          IN {i \in Ids : f[i]}
\* crypto §4: current = established, and no established rotation supersedes it.
Cur(x) == LET E == Est(x) IN {e \in E : ~\E f \in E : e \in ep[f].sup}
HeldCur(x) == Cur(x) \cap sec[x]
\* crypto §5: an uploader wraps under the newest current read epoch whose
\* secret it holds; a node holding none uses the newest established secret it
\* holds (its stranded heartbeat only). crypto §4: established epochs only.
EncEp(x) == NewestOf(IF HeldCur(x) # {} THEN HeldCur(x) ELSE sec[x] \cap Est(x))
\* crypto §4: an epoch covers a departure of M if it holds no box for M.
Covers(x, e) == \A m \in dep[x] : m \notin ep[e].boxes
\* crypto §5: a rotation commit is wrapped under the newest epoch it supersedes.
WrapOf(k) == NewestOf(ep[k].sup)
Top == steps[Len(steps)]
\* crypto §4: the history box holds "every distinct earlier secret of an
\* established epoch the rotator holds".
Hist(a) == sec[a] \cap Est(a)
Mem == (Nodes \ Late) \cup granted
\* sync §5 re-registration: an admin that holds the head's epoch and an
\* established epoch newer than it issues a child at its newest (crypto §4).
NeedsReg(a) == Top.ep \in sec[a] /\ HeldCur(a) # {} /\ Newer(EncEp(a), Top.ep)
\* sync §2/§5 open: a sync key of the head, or of the newest superseded step
\* bearing it, answered with its child; then claims at each later step (the
\* n round trips are one step here); a dropped claim set refuses the claim.
\* Opening is not encrypting under (crypto §4): any held secret opens.
CanOpen(x) ==
  \E j \in 1..Len(steps) :
    /\ steps[j].ep \in sec[x]
    /\ \A k \in (j + 1)..Len(steps) :
         steps[k].ep \in sec[x] \/ (x \in steps[k].cl /\ ~steps[k].dr)

\* Download of rotation commit k: readable under its wrap epoch. From the
\* server (after an open; InOrder: in log order) or, if ~InOrder, from an
\* online member peer y that holds it.
Readable(x, k) == k \notin kn[x] /\ WrapOf(k) \in sec[x]
FromSrv(x, k) == /\ CanOpen(x) /\ k \in srvRot /\ Readable(x, k)
                 /\ InOrder => \A j \in before[k] : WrapOf(j) \in sec[x] => j \in kn[x]
FromPeer(x, y, k) == ~InOrder /\ y # x /\ online[y] /\ k \in kn[y] /\ Readable(x, k)

\* permissions §3: re-seal is decided "at the end of a complete sync pass of
\* the actor's labels (one that read the log of every server and peer it
\* syncs them with to its end)": the server, and every member peer the node
\* has synced with (received from) that is online (R8).
SrvDone(a) == /\ CanOpen(a)
              /\ \A k \in srvRot : ~Readable(a, k)
              /\ \A g \in srvGrant : g[2] \in sec[a] => g[1] \in mem[a]
PeerDone(a, y) == \A k \in kn[y] : ~Readable(a, k)
FullPass(a) == SrvDone(a) /\ \A y \in via[a] : online[y] => PeerDone(a, y)

\* permissions §3 re-seal trigger: a current member seen without a box at a
\* current epoch, or whose heartbeat reports it stranded; only at epochs
\* established through their rotation commits (all of Est here).
Miss(a, m) == {e \in HeldCur(a) : m \notin ep[e].boxes}
ResealE(a, m) == IF Miss(a, m) # {} THEN Miss(a, m) ELSE HeldCur(a)
ResealWanted(a, m) ==
  /\ online[a] /\ m # a /\ m \in mem[a] \ dep[a] /\ FullPass(a)
  /\ Miss(a, m) # {} \/ m \in stranded

-----------------------------------------------------------------------------
Init ==
  /\ ep = [e \in Ids |-> IF e = 0
             THEN [n |-> 0, sup |-> {}, boxes |-> Nodes \ Late, ob |-> Nodes \ Late,
                   hist |-> {}, rem |-> {}]
             ELSE [n |-> 0, sup |-> {}, boxes |-> {}, ob |-> {}, hist |-> {}, rem |-> {}]]
  /\ made = {0}
  /\ kn = [x \in Nodes |-> {0}]
  /\ sec = [x \in Nodes |-> IF x \in Late THEN {} ELSE {0}]
  /\ dep = [x \in Nodes |-> {}]
  /\ mem = [x \in Nodes |-> Nodes \ Late]
  /\ removed = {} /\ granted = {}
  /\ srvRot = {} /\ before = [k \in Ids |-> {}] /\ srvGrant = {}
  /\ steps = <<[ep |-> 0, cl |-> Nodes \ Late, dr |-> FALSE]>>
  /\ inbox = {} /\ via = [x \in Nodes |-> {}] /\ stranded = {}
  /\ enc = {}
  /\ online = [x \in Nodes |-> TRUE]
  /\ budget = [w |-> 0, off |-> 0]

\* permissions §3 / crypto §4: fresh epoch n+1 superseding the current ones
\* of the rotator, boxed to every current member it knows, history box of
\* every established secret it holds. R: the removals this commit carries
\* (commits §2: a removal and the rotation it requires are one commit).
RotateR(a, R) ==
  /\ online[a] /\ Cardinality(made) <= MaxE
  /\ LET k == Cardinality(made)
         sup == Cur(a)
         d == dep[a] \cup R
     IN /\ ep' = [ep EXCEPT ![k] = [n |-> 1 + Max({ep[e].n : e \in sup}),
                    sup |-> sup, boxes |-> mem[a] \ d, ob |-> mem[a] \ d,
                    hist |-> Hist(a), rem |-> R]]
        /\ made' = made \cup {k}
        /\ kn' = [kn EXCEPT ![a] = @ \cup {k}]
        /\ sec' = [sec EXCEPT ![a] = @ \cup {k}]
        /\ dep' = [dep EXCEPT ![a] = d]
        /\ removed' = removed \cup R
  /\ UNCHANGED <<mem, granted, srvRot, before, srvGrant, steps, inbox, via, stranded, enc,
                 online, budget>>
Rotate(a) == RotateR(a, {})
Remove(m) == m \in Departing \ removed /\ RotateR(Remover, {m})
\* permissions §3 / crypto §4: MUST rotate before encrypting under an epoch
\* that does not cover a known departure: a content write (pending while the
\* budget lasts) or a re-seal box (boxing is encrypting under). MAY eagerly.
RotateForced(a) ==
  /\ \/ budget.w < Writes /\ ~Covers(a, EncEp(a))
     \/ \E m \in Nodes : ResealWanted(a, m) /\ \E e \in ResealE(a, m) : ~Covers(a, e)
  /\ Rotate(a)

\* sync §5: first upload the actor's membership commits it holds that the
\* server lacks (UploadRot), then register.
Register(a) ==
  /\ online[a] /\ NeedsReg(a) /\ kn[a] \ {0} \subseteq srvRot
  /\ steps' = Append(steps, [ep |-> EncEp(a), cl |-> ep[EncEp(a)].boxes, dr |-> FALSE])
  /\ UNCHANGED <<ep, made, kn, sec, dep, mem, removed, granted, srvRot, before, srvGrant,
                 inbox, via, stranded, enc, online, budget>>

\* sync §5: rotation commits go up under the head's keys (write key never
\* rotated here), before the step.
UploadRot(a, k) ==
  /\ online[a] /\ k \in kn[a] \ srvRot /\ k # 0
  \* permissions §3: a remover places the removal before any other upload.
  /\ \A j \in kn[a] \ srvRot : ep[j].rem # {} => j = k
  /\ srvRot' = srvRot \cup {k}
  /\ before' = [before EXCEPT ![k] = srvRot]
  /\ UNCHANGED <<ep, made, kn, sec, dep, mem, removed, granted, srvGrant, steps, inbox, via,
                 stranded, enc, online, budget>>

\* crypto §4: a grant writes the grantee's boxes at each current epoch (with
\* their history boxes), delivered by inbox; the grant commit goes under the
\* label wrapped under the granter's newest epoch. Unfair (a choice).
Grant(a, m) ==
  /\ online[a] /\ m \in Late \ granted /\ ~NeedsReg(a) /\ HeldCur(a) # {}
  /\ \A e \in HeldCur(a) : Covers(a, e)
  /\ granted' = granted \cup {m}
  /\ mem' = [mem EXCEPT ![a] = @ \cup {m}]
  /\ ep' = [e \in Ids |-> IF e \in HeldCur(a) THEN [ep[e] EXCEPT !.boxes = @ \cup {m}] ELSE ep[e]]
  /\ inbox' = inbox \cup {<<m, e>> : e \in HeldCur(a)}
  /\ srvGrant' = srvGrant \cup {<<m, EncEp(a)>>}
  /\ UNCHANGED <<made, kn, sec, dep, removed, srvRot, before, steps, via, stranded, enc,
                 online, budget>>

RecvGrant(x, g) ==
  /\ online[x] /\ CanOpen(x) /\ g \in srvGrant /\ g[1] \notin mem[x] /\ g[2] \in sec[x]
  /\ mem' = [mem EXCEPT ![x] = @ \cup {g[1]}]
  /\ UNCHANGED <<ep, made, kn, sec, dep, removed, granted, srvRot, before, srvGrant, steps,
                 inbox, via, stranded, enc, online, budget>>

\* crypto §4: never encrypt under an epoch that does not cover a known
\* departure; crypto §5: a node holding no current secret writes nothing.
WriteContent(a) ==
  /\ online[a] /\ budget.w < Writes /\ ~NeedsReg(a) /\ HeldCur(a) # {}
  /\ Covers(a, EncEp(a))
  /\ enc' = enc \cup {<<EncEp(a), dep[a]>>}
  /\ budget' = [budget EXCEPT !.w = @ + 1]
  /\ UNCHANGED <<ep, made, kn, sec, dep, mem, removed, granted, srvRot, before, srvGrant,
                 steps, inbox, via, stranded, online>>

\* A box for x gives the new secret and, by the history box, every secret the
\* rotator held; the removals it carries become known.
Apply(x, k) ==
  /\ kn' = [kn EXCEPT ![x] = @ \cup {k}]
  /\ sec' = [sec EXCEPT ![x] = @ \cup (IF x \in ep[k].boxes THEN {k} \cup ep[k].hist ELSE {})]
  /\ dep' = [dep EXCEPT ![x] = @ \cup ep[k].rem]
RecvSrv(x, k) ==
  /\ online[x] /\ FromSrv(x, k) /\ Apply(x, k)
  /\ UNCHANGED <<ep, made, mem, removed, granted, srvRot, before, srvGrant, steps, inbox,
                 via, stranded, enc, online, budget>>
RecvPeer(x, y, k) ==
  /\ online[x] /\ FromPeer(x, y, k) /\ Apply(x, k)
  /\ via' = [via EXCEPT ![x] = @ \cup {y}]
  /\ UNCHANGED <<ep, made, mem, removed, granted, srvRot, before, srvGrant, steps, inbox,
                 stranded, enc, online, budget>>
Recv(x, k) == RecvSrv(x, k) \/ \E y \in Nodes : RecvPeer(x, y, k)

\* permissions §3: SHOULD re-seal (treated as done: fair), by inbox only, with
\* the epochs' history boxes; boxing is encrypting under, so only at epochs
\* covering every departure the re-sealer knows.
Reseal(a, m) ==
  /\ ResealWanted(a, m)
  /\ \A e \in ResealE(a, m) : Covers(a, e)
  /\ ep' = [e \in Ids |-> IF e \in ResealE(a, m) THEN [ep[e] EXCEPT !.boxes = @ \cup {m}] ELSE ep[e]]
  /\ inbox' = inbox \cup {<<m, e>> : e \in ResealE(a, m)}
  /\ stranded' = stranded \ {m}
  /\ UNCHANGED <<made, kn, sec, dep, mem, removed, granted, srvRot, before, srvGrant, steps,
                 via, enc, online, budget>>

\* crypto §4: the grant or re-seal re-writes each boxed epoch's history box.
InboxRecv(m, e) ==
  /\ online[m] /\ <<m, e>> \in inbox
  /\ sec' = [sec EXCEPT ![m] = @ \cup {e} \cup ep[e].hist]
  /\ inbox' = inbox \ {<<m, e>>}
  /\ UNCHANGED <<ep, made, kn, dep, mem, removed, granted, srvRot, before, srvGrant, steps,
                 via, stranded, enc, online, budget>>

\* permissions §4: MUST place a stranded heartbeat when it cannot read the
\* current epoch: it reached the head and after a complete pass there cannot
\* open the epoch it registers, or a claim on the way was refused. By deposit
\* (no open needed), wrapped under the newest established held secret;
\* refused if the deposit seed was refreshed by a rotation whose /keys the
\* node has not read (crypto §3).
Heartbeat(x) ==
  /\ online[x] /\ x \in Mem /\ x \notin stranded /\ x \notin dep[x]
  /\ \/ CanOpen(x) /\ Top.ep \notin sec[x] /\ ~\E k \in srvRot : FromSrv(x, k)
     \/ ~CanOpen(x)
  /\ Refresh => Top.ep \in kn[x]
  /\ stranded' = stranded \cup {x}
  /\ UNCHANGED <<ep, made, kn, sec, dep, mem, removed, granted, srvRot, before, srvGrant,
                 steps, inbox, via, enc, online, budget>>

\* sync §4: a superseded step's claim set is kept MEMBERSHIP_KEEP, then may go.
Drop(i) ==
  /\ DropClaims /\ i < Len(steps) /\ ~steps[i].dr
  /\ steps' = [steps EXCEPT ![i].dr = TRUE]
  /\ UNCHANGED <<ep, made, kn, sec, dep, mem, removed, granted, srvRot, before, srvGrant,
                 inbox, via, stranded, enc, online, budget>>

GoOff(x) == /\ online[x] /\ budget.off < Offs
            /\ online' = [online EXCEPT ![x] = FALSE] /\ budget' = [budget EXCEPT !.off = @ + 1]
            /\ UNCHANGED <<ep, made, kn, sec, dep, mem, removed, granted, srvRot, before,
                           srvGrant, steps, inbox, via, stranded, enc>>
GoOn(x) == /\ ~online[x] /\ online' = [online EXCEPT ![x] = TRUE]
           /\ UNCHANGED <<ep, made, kn, sec, dep, mem, removed, granted, srvRot, before,
                          srvGrant, steps, inbox, via, stranded, enc, budget>>

Next ==
  \/ \E a \in Admins : Rotate(a) \/ Register(a) \/ WriteContent(a)
                       \/ (\E k \in Ids : UploadRot(a, k))
                       \/ (\E m \in Nodes : Reseal(a, m) \/ Grant(a, m))
  \/ \E m \in Departing : Remove(m)
  \/ \E x \in Nodes : \/ Heartbeat(x) \/ GoOff(x) \/ GoOn(x)
                      \/ (\E k \in Ids : Recv(x, k) \/ InboxRecv(x, k))
                      \/ (\E g \in srvGrant : RecvGrant(x, g))
  \/ \E i \in 1..Len(steps) : Drop(i)

\* Weak fairness of honest steps; eager rotation, removal, grants, writes,
\* claim-set drops and going offline are unfair.
Fairness ==
  /\ \A a \in Admins : /\ WF_vars(RotateForced(a)) /\ WF_vars(Register(a))
                       /\ \A k \in Ids : WF_vars(UploadRot(a, k))
                       /\ \A m \in Nodes : WF_vars(Reseal(a, m))
  /\ \A x \in Nodes : /\ WF_vars(Heartbeat(x)) /\ WF_vars(GoOn(x))
                      /\ \A k \in Ids : WF_vars(Recv(x, k)) /\ WF_vars(InboxRecv(x, k))
                      /\ WF_vars(\E g \in srvGrant : RecvGrant(x, g))

Spec == Init /\ [][Next]_vars /\ Fairness

-----------------------------------------------------------------------------
GCur == {e \in made : ~\E f \in made : e \in ep[f].sup}

TypeOK == /\ made \subseteq Ids /\ removed \subseteq Departing /\ granted \subseteq Late
          /\ \A x \in Nodes : sec[x] \subseteq made /\ kn[x] \subseteq made
                              /\ via[x] \subseteq Nodes

\* crypto §4 covers rule, its purpose: content a writer encrypted while it
\* knew of M's departure is never readable by M.
NoLeak == \A c \in enc : \A m \in c[2] : c[1] \notin sec[m]
\* permissions §3 "requires rotating every role secret M could open": a
\* departed member never holds an epoch whose rotation did not box it.
DepartedLocked == \A m \in removed : \A e \in sec[m] : m \in ep[e].ob

\* permissions §3 / sync §5: every current member eventually opens every
\* current epoch (by claims, downloads or re-seal) ...
CurrentOpens == <>[](\A x \in Mem \ removed : GCur \subseteq sec[x])
\* ... and reads the label: every epoch content was written under (for a
\* grantee, older epochs by the history box, crypto §4).
ReadsAll == <>[](\A x \in Mem \ removed : \A c \in enc : c[1] \in sec[x])
=============================================================================
