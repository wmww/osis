------------------------------- MODULE Rotation -------------------------------
(* Read-role rotation, removals, grants, label registration steps, claims and *)
(* re-seal for one actor whose label sits at one blind server (spec/crypto.md  *)
(* §3-§5, spec/sync.md §2 and §5, spec/permissions.md §3-§4, commits §2).      *)
(* Crypto is access: sec[x] is the set of epochs whose secret x holds; a box   *)
(* is a member in ep[e].ob or a grant or re-seal commit in bx; a wrap is the  *)
(* epoch a blob is under.                                                     *)
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
          Plants,     \* adversary: boxes planted by a non-member in a run
          InOrder     \* TRUE: one source, the server's log order (cursor sync);
                      \* FALSE: any order, and member peers serve rotations

Nodes == Admins \cup Readers
Ids == 0..MaxE
Max(S) == CHOOSE x \in S : \A y \in S : x >= y

VARIABLES ep,       \* ep[e] = [n, sup, ob, hist, rem]; ob = members the
                    \* rotation boxed; rem = removals the rotation commit carries
          made,     \* created epoch ids
          kn,       \* kn[x]: rotation commits x holds (0 always)
          sec,      \* sec[x]: epoch secrets x holds from applied valid boxes
          fsec,     \* fsec[x]: secrets x learned only from a planted box
          dep,      \* dep[x]: departures x knows of
          mem,      \* mem[x]: members x knows were granted
          removed,  \* departures that happened
          granted,  \* Late members granted so far
          srvRot,   \* rotation commits at the server
          before,   \* before[k]: rotations logged before rotation k's upload
          bx,       \* grant and re-seal commits under the label:
                    \* [m: member boxed, eps: epochs boxed, w: wrap epoch, g: grant]
          rd,       \* rd[x]: the commits of bx that x has read
          steps,    \* registration path: <<[ep, cl, dr]>>; dr = claim set dropped
          inbox,    \* grant and re-seal boxes in flight: <<member, epoch>>
          inRot,    \* rotation commits in flight by inbox: <<member, rotation>>
          via,      \* via[x]: member peers x received rotation commits from
          stranded, \* members whose stranded heartbeat is under the label
          enc,      \* content written: <<epoch, departures the writer knew>>
          leakP,    \* TRUE once something was encrypted under a planted secret
          online, budget
vars == <<ep, made, kn, sec, fsec, dep, mem, removed, granted, srvRot, before, bx, rd,
          steps, inbox, inRot, via, stranded, enc, leakP, online, budget>>

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
\* crypto §4: "A secret learned only from a pending or invalid commit is kept
\* for reading and never encrypted under until an applied valid box carries
\* it." Enc(x) is what x may encrypt under: secrets from applied valid boxes
\* only, never fsec (README: negative control with sec[x] \cup fsec[x]).
Enc(x) == sec[x]
HeldCur(x) == Cur(x) \cap Enc(x)
\* crypto §5: an uploader wraps under the newest current read epoch whose
\* secret it holds; a node holding none uses the newest established secret it
\* holds (its stranded heartbeat only). crypto §4: established epochs only.
EncEp(x) == NewestOf(IF HeldCur(x) # {} THEN HeldCur(x) ELSE Enc(x) \cap Est(x))
\* The boxes x knows of: those of the rotation commits it applied and of the
\* grant and re-seal commits it read (permissions §3: a re-seal goes under
\* the actor's labels, so every node learns its boxes).
Holders(x, e) == (IF e \in kn[x] THEN ep[e].ob ELSE {})
                 \cup {b.m : b \in {c \in rd[x] : e \in c.eps}}
\* crypto §4: an epoch covers a departure of M if it holds no box for M. A
\* rotator always boxes itself, so "an epoch whose rotation commit was written
\* by a departed party does not cover that party's departure" adds nothing
\* here (no departures inside a member, ASSUMPTIONS.md).
Covers(x, e) == \A m \in dep[x] : m \notin Holders(x, e)
\* crypto §5: a rotation commit is wrapped under the newest epoch it supersedes.
WrapOf(k) == NewestOf(ep[k].sup)
Top == steps[Len(steps)]
\* crypto §4: the history box holds "every distinct earlier secret of an
\* established epoch the rotator holds".
Hist(a) == Enc(a) \cap Est(a)
Mem == (Nodes \ Late) \cup granted
\* sync §5 re-registration: an admin that holds the head's epoch and an
\* established epoch newer than it issues a child at its newest (crypto §4).
NeedsReg(a) == Top.ep \in Enc(a) /\ HeldCur(a) # {} /\ Newer(EncEp(a), Top.ep)
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
              /\ \A b \in bx : b.w \in sec[a] => b \in rd[a]
PeerDone(a, y) == \A k \in kn[y] : ~Readable(a, k)
FullPass(a) == SrvDone(a) /\ \A y \in via[a] : online[y] => PeerDone(a, y)

\* permissions §3 re-seal trigger: a current member seen without a box at a
\* current epoch, or whose heartbeat reports it stranded; only at epochs
\* established through their rotation commits (all of Est here).
Miss(a, m) == {e \in HeldCur(a) : m \notin Holders(a, e)}
ResealE(a, m) == IF Miss(a, m) # {} THEN Miss(a, m) ELSE HeldCur(a)
ResealWanted(a, m) ==
  /\ online[a] /\ m # a /\ m \in mem[a] \ dep[a] /\ FullPass(a)
  /\ Miss(a, m) # {} \/ m \in stranded

-----------------------------------------------------------------------------
Init ==
  /\ ep = [e \in Ids |-> IF e = 0
             THEN [n |-> 0, sup |-> {}, ob |-> Nodes \ Late, hist |-> {}, rem |-> {}]
             ELSE [n |-> 0, sup |-> {}, ob |-> {}, hist |-> {}, rem |-> {}]]
  /\ made = {0}
  /\ kn = [x \in Nodes |-> {0}]
  /\ sec = [x \in Nodes |-> IF x \in Late THEN {} ELSE {0}]
  /\ fsec = [x \in Nodes |-> {}]
  /\ dep = [x \in Nodes |-> {}]
  /\ mem = [x \in Nodes |-> Nodes \ Late]
  /\ removed = {} /\ granted = {}
  /\ srvRot = {} /\ before = [k \in Ids |-> {}] /\ bx = {} /\ rd = [x \in Nodes |-> {}]
  /\ steps = <<[ep |-> 0, cl |-> Nodes \ Late, dr |-> FALSE]>>
  /\ inbox = {} /\ inRot = {} /\ via = [x \in Nodes |-> {}] /\ stranded = {}
  /\ enc = {} /\ leakP = FALSE
  /\ online = [x \in Nodes |-> TRUE]
  /\ budget = [w |-> 0, off |-> 0, p |-> 0]

\* permissions §3 / crypto §4: fresh epoch n+1 superseding the current ones
\* of the rotator, boxed to every current member it knows, history box of
\* every established secret it holds. R: the removals this commit carries
\* (commits §2: a removal and the rotation it requires are one commit).
\* permissions §3: a member it boxes that holds no box at a current read epoch
\* before it (as the rotator knows) also gets the rotation by inbox.
RotateR(a, R) ==
  /\ online[a] /\ Cardinality(made) <= MaxE
  /\ LET k == Cardinality(made)
         sup == Cur(a)
         d == dep[a] \cup R
         ob == mem[a] \ d
     IN /\ ep' = [ep EXCEPT ![k] = [n |-> 1 + Max({ep[e].n : e \in sup}),
                    sup |-> sup, ob |-> ob, hist |-> Hist(a), rem |-> R]]
        /\ made' = made \cup {k}
        /\ kn' = [kn EXCEPT ![a] = @ \cup {k}]
        /\ sec' = [sec EXCEPT ![a] = @ \cup {k}]
        /\ dep' = [dep EXCEPT ![a] = d]
        /\ removed' = removed \cup R
        /\ inRot' = inRot \cup {<<m, k>> : m \in {y \in ob \ {a} :
                                   \A e \in sup : y \notin Holders(a, e)}}
        /\ leakP' = (leakP \/ ~(Hist(a) \subseteq sec[a]))
  /\ UNCHANGED <<fsec, mem, granted, srvRot, before, bx, rd, steps, inbox, via, stranded, enc,
                 online, budget>>
Rotate(a) == RotateR(a, {})
Remove(m) == m \in Departing \ removed /\ RotateR(Remover, {m})
\* permissions §3 / crypto §4: MUST rotate before encrypting under an epoch
\* that does not cover a known departure: a content write (pending while the
\* budget lasts) or a re-seal box (boxing is encrypting under). MAY eagerly.
RotateForced(a) ==
  /\ \/ budget.w < Writes /\ ~Covers(a, EncEp(a))
     \/ \E m \in Nodes : ResealWanted(a, m) /\ \E e \in ResealE(a, m) \cup {EncEp(a)} : ~Covers(a, e)
  /\ Rotate(a)

\* sync §5: first upload the actor's membership commits it holds that the
\* server lacks (UploadRot), then register.
Register(a) ==
  /\ online[a] /\ NeedsReg(a) /\ kn[a] \ {0} \subseteq srvRot
  /\ steps' = Append(steps, [ep |-> EncEp(a), cl |-> Holders(a, EncEp(a)), dr |-> FALSE])
  /\ leakP' = (leakP \/ ~({Top.ep, EncEp(a)} \subseteq sec[a]))
  /\ UNCHANGED <<ep, made, kn, sec, fsec, dep, mem, removed, granted, srvRot, before, bx, rd,
                 inbox, inRot, via, stranded, enc, online, budget>>

\* sync §5: rotation commits go up under the head's keys (write key never
\* rotated here), before the step.
UploadRot(a, k) ==
  /\ online[a] /\ k \in kn[a] \ srvRot /\ k # 0
  \* permissions §3: a remover places the removal before any other upload.
  /\ \A j \in kn[a] \ srvRot : ep[j].rem # {} => j = k
  /\ srvRot' = srvRot \cup {k}
  /\ before' = [before EXCEPT ![k] = srvRot]
  /\ UNCHANGED <<ep, made, kn, sec, fsec, dep, mem, removed, granted, bx, rd, steps, inbox,
                 inRot, via, stranded, enc, leakP, online, budget>>

\* A grant or re-seal commit b by a: placed under the label (wrapped under a's
\* newest epoch), read by a at once, boxes delivered to b.m by inbox.
PlaceBox(a, b) ==
  /\ bx' = bx \cup {b}
  /\ rd' = [rd EXCEPT ![a] = @ \cup {b}]
  /\ inbox' = inbox \cup {<<b.m, e>> : e \in b.eps}
  /\ leakP' = (leakP \/ ~(b.eps \cup {b.w} \subseteq sec[a]))

\* crypto §4: a grant writes the grantee's boxes at each current epoch (with
\* their history boxes), delivered by inbox; the grant commit goes under the
\* label wrapped under the granter's newest epoch. Unfair (a choice).
Grant(a, m) ==
  /\ online[a] /\ m \in Late \ granted /\ ~NeedsReg(a) /\ HeldCur(a) # {}
  /\ \A e \in HeldCur(a) : Covers(a, e)
  /\ granted' = granted \cup {m}
  /\ mem' = [mem EXCEPT ![a] = @ \cup {m}]
  /\ PlaceBox(a, [m |-> m, eps |-> HeldCur(a), w |-> EncEp(a), g |-> TRUE])
  /\ UNCHANGED <<ep, made, kn, sec, fsec, dep, removed, srvRot, before, steps, inRot, via,
                 stranded, enc, online, budget>>

\* Reading a grant or re-seal commit from the label: a grant teaches the
\* member; the boxed member itself takes the secrets and history boxes.
RecvBox(x, b) ==
  /\ online[x] /\ CanOpen(x) /\ b \in bx \ rd[x] /\ b.w \in sec[x]
  /\ rd' = [rd EXCEPT ![x] = @ \cup {b}]
  /\ mem' = IF b.g THEN [mem EXCEPT ![x] = @ \cup {b.m}] ELSE mem
  /\ sec' = IF b.m = x THEN [sec EXCEPT ![x] = @ \cup b.eps \cup UNION {ep[e].hist : e \in b.eps}]
            ELSE sec
  /\ UNCHANGED <<ep, made, kn, fsec, dep, removed, granted, srvRot, before, bx, steps,
                 inbox, inRot, via, stranded, enc, leakP, online, budget>>

\* crypto §4: never encrypt under an epoch that does not cover a known
\* departure; crypto §5: a node holding no current secret writes nothing.
WriteContent(a) ==
  /\ online[a] /\ budget.w < Writes /\ ~NeedsReg(a) /\ HeldCur(a) # {}
  /\ Covers(a, EncEp(a))
  /\ enc' = enc \cup {<<EncEp(a), dep[a]>>}
  /\ leakP' = (leakP \/ EncEp(a) \notin sec[a])
  /\ budget' = [budget EXCEPT !.w = @ + 1]
  /\ UNCHANGED <<ep, made, kn, sec, fsec, dep, mem, removed, granted, srvRot, before, bx, rd,
                 steps, inbox, inRot, via, stranded, online>>

\* A box for x gives the new secret and, by the history box, every secret the
\* rotator held; the removals it carries become known.
Apply(x, k) ==
  /\ kn' = [kn EXCEPT ![x] = @ \cup {k}]
  /\ sec' = [sec EXCEPT ![x] = @ \cup (IF x \in ep[k].ob THEN {k} \cup ep[k].hist ELSE {})]
  /\ dep' = [dep EXCEPT ![x] = @ \cup ep[k].rem]
RecvSrv(x, k) ==
  /\ online[x] /\ FromSrv(x, k) /\ Apply(x, k)
  /\ UNCHANGED <<ep, made, fsec, mem, removed, granted, srvRot, before, bx, rd, steps, inbox,
                 inRot, via, stranded, enc, leakP, online, budget>>
RecvPeer(x, y, k) ==
  /\ online[x] /\ FromPeer(x, y, k) /\ Apply(x, k)
  /\ via' = [via EXCEPT ![x] = @ \cup {y}]
  /\ UNCHANGED <<ep, made, fsec, mem, removed, granted, srvRot, before, bx, rd, steps, inbox,
                 inRot, stranded, enc, leakP, online, budget>>
\* permissions §3: a rotation delivered by inbox (no label access needed).
InboxRot(x, k) ==
  /\ online[x] /\ <<x, k>> \in inRot /\ Apply(x, k)
  /\ inRot' = inRot \ {<<x, k>>}
  /\ UNCHANGED <<ep, made, fsec, mem, removed, granted, srvRot, before, bx, rd, steps, inbox,
                 via, stranded, enc, leakP, online, budget>>
Recv(x, k) == RecvSrv(x, k) \/ \E y \in Nodes : RecvPeer(x, y, k)

\* permissions §3: SHOULD re-seal (treated as done: fair), with the epochs'
\* history boxes, delivered by inbox and placed under the actor's labels like
\* any membership commit (wrapped under the newest epoch); boxing and that
\* wrap are encrypting under, so only at epochs covering every departure the
\* re-sealer knows.
Reseal(a, m) ==
  /\ ResealWanted(a, m) /\ HeldCur(a) # {}
  /\ \A e \in ResealE(a, m) \cup {EncEp(a)} : Covers(a, e)
  /\ PlaceBox(a, [m |-> m, eps |-> ResealE(a, m), w |-> EncEp(a), g |-> FALSE])
  /\ stranded' = stranded \ {m}
  /\ UNCHANGED <<ep, made, kn, sec, fsec, dep, mem, removed, granted, srvRot, before, steps,
                 inRot, via, enc, online, budget>>

\* crypto §4: the grant or re-seal re-writes each boxed epoch's history box.
InboxRecv(m, e) ==
  /\ online[m] /\ <<m, e>> \in inbox
  /\ sec' = [sec EXCEPT ![m] = @ \cup {e} \cup ep[e].hist]
  /\ inbox' = inbox \ {<<m, e>>}
  /\ UNCHANGED <<ep, made, kn, fsec, dep, mem, removed, granted, srvRot, before, bx, rd, steps,
                 inRot, via, stranded, enc, leakP, online, budget>>

\* Adversary (crypto §4): anyone can seal a box to a member's /keys in a
\* commit that stays pending or is invalid, naming an existing epoch with a
\* secret of its choosing; the member keeps it for reading only (fsec).
Plant(x, e) ==
  /\ budget.p < Plants /\ e \in made /\ e \notin sec[x] \cup fsec[x]
  /\ fsec' = [fsec EXCEPT ![x] = @ \cup {e}]
  /\ budget' = [budget EXCEPT !.p = @ + 1]
  /\ UNCHANGED <<ep, made, kn, sec, dep, mem, removed, granted, srvRot, before, bx, rd, steps,
                 inbox, inRot, via, stranded, enc, leakP, online>>

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
  /\ Enc(x) \cap Est(x) # {}
  /\ stranded' = stranded \cup {x}
  /\ leakP' = (leakP \/ NewestOf(Enc(x) \cap Est(x)) \notin sec[x])
  /\ UNCHANGED <<ep, made, kn, sec, fsec, dep, mem, removed, granted, srvRot, before, bx, rd,
                 steps, inbox, inRot, via, enc, online, budget>>

\* sync §4: a superseded step's claim set is kept MEMBERSHIP_KEEP, then may go.
Drop(i) ==
  /\ DropClaims /\ i < Len(steps) /\ ~steps[i].dr
  /\ steps' = [steps EXCEPT ![i].dr = TRUE]
  /\ UNCHANGED <<ep, made, kn, sec, fsec, dep, mem, removed, granted, srvRot, before, bx, rd,
                 inbox, inRot, via, stranded, enc, leakP, online, budget>>

GoOff(x) == /\ online[x] /\ budget.off < Offs
            /\ online' = [online EXCEPT ![x] = FALSE] /\ budget' = [budget EXCEPT !.off = @ + 1]
            /\ UNCHANGED <<ep, made, kn, sec, fsec, dep, mem, removed, granted, srvRot, before,
                           bx, rd, steps, inbox, inRot, via, stranded, enc, leakP>>
GoOn(x) == /\ ~online[x] /\ online' = [online EXCEPT ![x] = TRUE]
           /\ UNCHANGED <<ep, made, kn, sec, fsec, dep, mem, removed, granted, srvRot, before,
                          bx, rd, steps, inbox, inRot, via, stranded, enc, leakP, budget>>

Next ==
  \/ \E a \in Admins : Rotate(a) \/ Register(a) \/ WriteContent(a)
                       \/ (\E k \in Ids : UploadRot(a, k))
                       \/ (\E m \in Nodes : Reseal(a, m) \/ Grant(a, m))
  \/ \E m \in Departing : Remove(m)
  \/ \E x \in Nodes : \/ Heartbeat(x) \/ GoOff(x) \/ GoOn(x)
                      \/ (\E k \in Ids : Recv(x, k) \/ InboxRecv(x, k) \/ InboxRot(x, k)
                                         \/ Plant(x, k))
                      \/ (\E b \in bx : RecvBox(x, b))
  \/ \E i \in 1..Len(steps) : Drop(i)

\* Weak fairness of honest steps; eager rotation, removal, grants, writes,
\* claim-set drops, going offline and planting are unfair.
Fairness ==
  /\ \A a \in Admins : /\ WF_vars(RotateForced(a)) /\ WF_vars(Register(a))
                       /\ \A k \in Ids : WF_vars(UploadRot(a, k))
                       /\ \A m \in Nodes : WF_vars(Reseal(a, m))
  /\ \A x \in Nodes : /\ WF_vars(Heartbeat(x)) /\ WF_vars(GoOn(x))
                      /\ \A k \in Ids : /\ WF_vars(Recv(x, k)) /\ WF_vars(InboxRecv(x, k))
                                       /\ WF_vars(InboxRot(x, k))
                      /\ WF_vars(\E b \in bx : RecvBox(x, b))

Spec == Init /\ [][Next]_vars /\ Fairness

-----------------------------------------------------------------------------
GCur == {e \in made : ~\E f \in made : e \in ep[f].sup}

TypeOK == /\ made \subseteq Ids /\ removed \subseteq Departing /\ granted \subseteq Late
          /\ \A x \in Nodes : sec[x] \subseteq made /\ kn[x] \subseteq made
                              /\ fsec[x] \subseteq made /\ via[x] \subseteq Nodes
                              /\ rd[x] \subseteq bx

\* crypto §4 covers rule, its purpose: content a writer encrypted while it
\* knew of M's departure is never readable by M.
NoLeak == \A c \in enc : \A m \in c[2] : c[1] \notin sec[m]
\* permissions §3 "requires rotating every role secret M could open": a
\* departed member never holds an epoch whose rotation did not box it.
DepartedLocked == \A m \in removed : \A e \in sec[m] : m \in ep[e].ob
\* crypto §4: a secret from a planted box (a non-member's pending or invalid
\* commit) never becomes an encrypting key: nothing was wrapped, boxed,
\* history-boxed or signed under it.
NoPlantedKey == ~leakP

\* permissions §3 / sync §5: every current member eventually opens every
\* current epoch (by claims, downloads or re-seal) ...
CurrentOpens == <>[](\A x \in Mem \ removed : GCur \subseteq sec[x])
\* ... and reads the label: every epoch content was written under (for a
\* grantee, older epochs by the history box, crypto §4).
ReadsAll == <>[](\A x \in Mem \ removed : \A c \in enc : c[1] \in sec[x])
=============================================================================
