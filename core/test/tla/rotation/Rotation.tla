------------------------------- MODULE Rotation -------------------------------
(* Read-role rotation, removals, grants, label registration steps, claims and *)
(* re-seal for one actor whose label sits at one host (spec/crypto.md         *)
(* §3-§5, spec/sync.md §2 and §5, spec/permissions.md §3-§4, commits §2).      *)
(* Crypto is access: sec[x] is the set of epochs whose secret x holds; a box   *)
(* is a holder in ep[e].ob or a grant or re-seal commit in bx; a wrap is the  *)
(* epoch a blob is under.                                                     *)
EXTENDS Naturals, FiniteSets, Sequences

CONSTANTS Admins,     \* may rotate, register, grant, write content
          Readers,    \* read-only holders
          Late,       \* holders granted later (not boxed at epoch 0)
          Remover,    \* the admin that may remove
          Departing,  \* holders it may remove
          MaxE,       \* epoch ids 0..MaxE (0 = the initial epoch)
          Writes,     \* content writes in a run
          DropClaims, \* TRUE: the host may drop superseded steps' claim sets
          Refresh,    \* TRUE: every rotation refreshes the deposit seed (a MAY)
          Offs,       \* offline transitions in a run
          Plants,     \* adversary: boxes planted by a non-holder in a run
          InOrder,    \* TRUE: one source, the host's log order (cursor sync);
                      \* FALSE: any order, and co-reader peers serve rotations
          Groups,     \* readers that are holder actors: a device d, an admin
                      \* of one, may leave it (its keyset moves from epoch 0
                      \* to 1 in the removal R_P)
          Withhold,   \* admins the host and peers withhold every removal,
                      \* R_P included, from, forever
          OwnNames,   \* negative control: a rotation names only itself
          KeysetNames,\* FALSE: negative control, no keyset names
          GroupNames, \* FALSE: negative control, a rotation names no departure
                      \* from the group (the departures inside holders)
          KeysetBy,   \* "epoch": a keyset name is met by a held valid keyset
                      \* writing or superseding it; "commit": only by the
                      \* commit that wrote it (negative control)
          GActs,      \* group events beside d leaving: "rot" its admin
                      \* rotates it again (keyset 2), "forge" d, removed,
                      \* writes keyset 3 superseding every keyset made,
                      \* "snap" a node gets a roster snapshot of the group
                      \* made after R_P (not R_P), "fork" an admin of g
                      \* that has not seen R_P rotates g from keyset 0 to 4
                      \* (a fork of 1, boxing d; LWW-newer in keys.0)
          Frozen,     \* TRUE: frozen coverage (an epoch covers exactly the
                      \* departures it names; boxes to g carry names);
                      \* FALSE: the box-inspection covers rule
          Split,      \* TRUE: R_P reaches A's admins as two parts: its
                      \* keys.0 delta (body 1, LearnK) and its roles.0 delta
                      \* (the departure, LearnRP; never to Withhold)
          GrantNames, \* FALSE: negative control, grant and re-seal boxes
                      \* to g carry no names
          NoBoxCovers,\* TRUE: negative control, under Frozen a holder with
                      \* no box at e counts as covered (the old base case)
          GNamesBy,   \* Frozen: whose names a boxer of g must hold:
                      \* "current" the study's rule (every grant or re-seal
                      \* box to g at a current epoch it holds), "grant" every
                      \* grant of g it holds (a grant leaving g out is
                      \* refused)
          Proj,       \* a grant of g may reach an admin as its edge alone
                      \* (a projection: the boxes deposited, never received):
                      \* "none" never; "bound" a node holding no box to g
                      \* carrying names then seals g only to the keyset g's
                      \* roster entry names (crypto §4), its box carrying
                      \* none; "free": at its own choice (negative control)
          Descent,    \* TRUE: keyset descent (notes/roster-names.md): a
                      \* keyset signs, under the delete key of each superseded
                      \* epoch whose secret its writer held, that it was
                      \* written knowing it; rotations name no departure from
                      \* g unless they leave g out; a boxer of g seals only to
                      \* a keyset descending from every keyset named for g
                      \* (its anchors), judged by descent from R_P's keyset
          Sigs        \* FALSE: negative control under Descent, descent read
                      \* from the listed epochs alone (d's forgery descends
                      \* from what it lists)

Nodes == Admins \cup Readers
Ids == 0..MaxE
Max(S) == CHOOSE x \in S : \A y \in S : x >= y

VARIABLES ep,       \* ep[e] = [n, sup, ob, hist, rem]; ob = holders the
                    \* rotation boxed; rem = removals the rotation commit carries
          made,     \* created epoch ids
          kn,       \* kn[x]: rotation commits x holds (0 always)
          sec,      \* sec[x]: epoch secrets x holds from applied valid boxes
          fsec,     \* fsec[x]: secrets x learned only from a planted box
          dep,      \* dep[x]: departures x knows of
          hld,      \* hld[x]: holders x knows were granted
          removed,  \* departures that happened
          granted,  \* Late holders granted so far
          hostRot,  \* rotation commits at the host
          before,   \* before[k]: rotations logged before rotation k's upload
          bx,       \* grant and re-seal commits under the label:
                    \* [m: holder boxed, eps: epochs boxed, w: wrap epoch, g: grant]
          rd,       \* rd[x]: the commits of bx that x has read
          steps,    \* registration path: <<[ep, cl, dr]>>; dr = claim set dropped
          inbox,    \* grant and re-seal boxes in flight: <<holder, epoch>>
          inRot,    \* rotation commits in flight by inbox: <<holder, rotation>>
          via,      \* via[x]: co-reader peers x received rotation commits from
          stranded, \* holders whose stranded heartbeat is under the label
          enc,      \* content written: <<epoch, departures the writer knew,
                    \* whether it knew d left the group>>
          leakP,    \* TRUE once something was encrypted under a planted secret
          gm,       \* the group's keyset epochs made: 0, 1 (R_P: d left),
                    \* 2 (a later rotation), 3 (d's forgery)
          fsup,     \* the epochs keyset 3 lists as superseded
          ks,       \* ks[x]: the group's keyset bodies x holds
          gd,       \* gd[x]: x holds R_P (knows d left the group)
          gs,       \* gs[x]: x holds a roster snapshot of the group after R_P
                    \* (gd[x]: with Split, x holds R_P's roles.0 part)
          pj,       \* pj[x]: grant commits of bx x holds as their edge alone
          rk,       \* rk[x]: the keyset epoch g's roster entry names at x
                    \* (the edge's `keyset`; 5: none, or one nobody holds)
          online, budget
vars == <<ep, made, kn, sec, fsec, dep, hld, removed, granted, hostRot, before, bx, rd,
          steps, inbox, inRot, via, stranded, enc, leakP, gm, fsup, ks, gd, gs, pj, rk, online, budget>>
gvars == <<gm, fsup, ks, gd, gs, pj, rk>>

ep_n(e) == ep[e].n
\* crypto §4: newest = greatest n, ties by lowest nonce (here: lowest id).
Newer(e, f) == ep_n(e) > ep_n(f) \/ (ep_n(e) = ep_n(f) /\ e < f)
NewestOf(S) == CHOOSE e \in S : \A f \in S \ {e} : Newer(e, f)
\* crypto §4: "A secret learned only from a pending or invalid commit is kept
\* for reading and never encrypted under until an applied valid box carries
\* it." Enc(x) is what x may encrypt under: secrets from applied valid boxes
\* only, never fsec (README: negative control with sec[x] \cup fsec[x]).
Enc(x) == sec[x]
\* permissions §5.2: d's keyset (written after its removal) is valid where
\* neither R_P nor an epoch start of the group after it is held (the
\* snapshot's ledger ends d's admin tenure).
VK(x) == ks[x] \ (IF gd[x] \/ gs[x] THEN {3} ELSE {})
\* The group's keyset epoch x boxes it at: its newest valid held (crypto §4;
\* ids follow n, keyset 3 is d's choice of n 3).
GK(x) == Max(VK(x))
GSup(k) == CASE k = 0 -> {} [] k = 1 -> {0} [] k = 2 -> {0, 1} [] k = 3 -> fsup [] k = 4 -> {0}
\* Descent: the epochs keyset k carries a valid descent signature for: those
\* its writer held the secret of. d, removed at R_P, holds secret of epoch 0 only, so
\* its forgery 3 descends from 0 whatever it lists (Sigs; without them, from
\* what it lists); the ignorant fork 4 from 0; 2 from 0 and 1.
Desc(k) == CASE k = 0 -> {} [] k = 1 -> {0} [] k = 2 -> {0, 1}
             [] k = 3 -> (IF Sigs THEN {0} ELSE fsup) [] k = 4 -> {0} [] k = 5 -> {}
\* The keysets k is or descends from, through bodies x holds (a signature
\* under j's delete key is checked with j's body, or with the key a keyset
\* name carries: the first hop needs no body).
Reach(x, k) == {k} \cup Desc(k) \cup UNION {Desc(j) : j \in Desc(k) \cap ks[x]}
\* Descent, the box judgement by knowledge: a keyset keeps d out when it is or
\* descends from the keyset d's removal wrote (1), judged from held bodies.
Keeps(x, k) == 1 \in Reach(x, k)
\* crypto §4: a keyset name is met by a held valid keyset body writing that
\* epoch or listing it as superseded ("commit": by that epoch's body alone;
\* Descent: listing it with a valid descent signature).
KMet(x, k) == IF Descent THEN \E b \in VK(x) : b = k \/ k \in Desc(b)
              ELSE IF KeysetBy = "epoch" THEN \E b \in VK(x) : b = k \/ k \in GSup(b)
              ELSE k \in VK(x)
\* crypto §4: an epoch is established at x when x applied its rotation commit
\* and, if x holds its secret, its names are met: x holds every removal its
\* rotator held (ep[i].nm, rotation commits; the commit itself carries its own:
\* the departs mark), the departure from the group its rotator held (ep[i].ng:
\* R_P, or an epoch start of the group after it) and the group's keyset epoch
\* its box to the group named (ep[i].nk). Own rotations are in kn at once; no
\* rotation commit is invalid; the actor itself has no epoch starts (roster
\* snapshots) nor secrets.0 snapshots (ASSUMPTIONS.md). Epoch 0 is the
\* derived epoch.
Est(x) == {0} \cup {i \in kn[x] : i \notin Enc(x) \/ (ep[i].nm \subseteq kn[x]
                                    /\ (ep[i].ng => gd[x] \/ gs[x])
                                    /\ \A k \in ep[i].nk : KMet(x, k))}
\* crypto §4: current = established, and no established rotation supersedes it.
Cur(x) == LET E == Est(x) IN {e \in E : ~\E f \in E : e \in ep[f].sup}
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
\* The group's keyset epochs x knows a box at e to a group names.
GBoxes(x, e) == (IF e \in kn[x] /\ ep[e].ob \cap Groups # {} THEN {ep[e].gk} ELSE {})
                \cup {b.gk : b \in {c \in rd[x] : e \in c.eps /\ c.m \in Groups}}
\* The box rule (crypto §4 before frozen coverage, the _box cfgs): an epoch
\* covers a departure of M if it holds no box for M, and
\* d's departure inside the group if its box to the group names a keyset
\* epoch d holds no box in (1, made by d's removal, or 2): not 0, nor 3,
\* written by d (departed). A roster snapshot alone tells x nothing here (as
\* for a reader's departure: no ledger entry), so only R_P counts.
CoversBox(x, e) == /\ \A m \in dep[x] : m \notin Holders(x, e)
                   /\ gd[x] => GBoxes(x, e) \cap {0, 3, 4} = {}
\* Frozen coverage (notes/epoch-establishment-study.md §3): e covers exactly
\* the departures its names name: the removals carried by the rotation
\* commits its rotator held (nm) and by itself (the departs mark), and d's
\* departure from g when its rotator held R_P (or a snapshot after it) while
\* g was below A there (ng). Boxes decide nothing (NoBoxCovers: the old base
\* case back, a negative control). A departure inside g counts only while g
\* is a holder of A as x knows.
NamedRem(e) == UNION {ep[j].rem : j \in ep[e].nm} \cup ep[e].rem
\* Descent: d's departure is covered by name (the rotation left g out and
\* named it) or when every box to g at e x knows names a keyset that keeps d
\* out, and there is one (no box to g is never "excluded").
CoversFrozen(x, e) ==
  /\ \A m \in dep[x] : m \in NamedRem(e) \/ (NoBoxCovers /\ m \notin Holders(x, e))
  /\ gd[x] /\ Groups \cap hld[x] # {} =>
       \/ ep[e].ng
       \/ Descent /\ GBoxes(x, e) # {} /\ \A k \in GBoxes(x, e) : Keeps(x, k)
Covers(x, e) == IF Frozen THEN CoversFrozen(x, e) ELSE CoversBox(x, e)
\* permissions §3 Left out: x boxes g only at a keyset it judges covering d's
\* departure, when it knows it (0 and the ignorant fork 4 box d; 3 is d's);
\* Frozen: and only holding the names of every grant or re-seal box to g at
\* a current epoch it holds (it knows R_P where one names it; a rotation's
\* names are held through establishment).
\* crypto §4: every box to g carries its sealer's names unless sealed bound
\* (fr). x seals g free holding such a box (a grant's it read, one at a
\* current epoch it holds, a free rotation's it applied); holding none (the
\* grant's boxes deposited and never received, pj; or every box held sealed
\* bound) it seals g bound: only to the keyset g's roster entry names (rk,
\* the last grant's choice), holding that keyset valid, and, knowing d left,
\* only if it is the newest it holds and keeps d out.
Free(x) == \/ \E b \in rd[x] : b.m \in Groups /\ b.fr /\ (b.g \/ b.eps \cap HeldCur(x) # {})
           \/ \E e \in HeldCur(x) \cap kn[x] : ep[e].ob \cap Groups # {} /\ ep[e].fr
Bound(x) == Proj # "free" /\ Groups \cap hld[x] # {} /\ ~Free(x)
\* Descent: x's anchors for g, the keyset names of the current epochs it holds
\* (a rotation that left g out carried its own anchors forward) and of the
\* free grant and re-seal boxes to g it read at them; it seals g only to a
\* held valid keyset that is or descends from every anchor, the newest (5:
\* none).
Anchors(x) == UNION {ep[e].nk : e \in HeldCur(x) \cap kn[x]}
              \cup {b.gk : b \in {c \in rd[x] : c.m \in Groups /\ c.fr
                                               /\ (c.g \/ c.eps \cap HeldCur(x) # {})}}
Cand(x) == {k \in VK(x) : \A a \in Anchors(x) : a \in Reach(x, k)}
SealK(x) == IF Bound(x) THEN rk[x]
            ELSE IF ~Descent THEN GK(x)
            ELSE IF Cand(x) = {} THEN 5 ELSE Max(Cand(x))
BoundOK(x) == Bound(x) => rk[x] \in VK(x) /\ (~Descent /\ gd[x] => rk[x] = GK(x))
GOK(x) == gd[x] => IF Descent THEN Keeps(x, SealK(x)) ELSE SealK(x) \notin {0, 3, 4}
GNamesOK(x) == \A b \in rd[x] :
                 (/\ b.m \in Groups /\ b.kd
                  /\ IF GNamesBy = "grant" THEN b.g ELSE b.eps \cap HeldCur(x) # {})
                 => gd[x] \/ gs[x]
BoxG(x) == /\ GOK(x) /\ BoundOK(x)
           /\ IF Descent THEN Bound(x) \/ Cand(x) # {} ELSE Frozen => GNamesOK(x)
\* crypto §5: a rotation commit is wrapped under the newest epoch it supersedes.
WrapOf(k) == NewestOf(ep[k].sup)
Top == steps[Len(steps)]
\* crypto §4: the history box holds "every distinct earlier secret of an
\* established epoch the rotator holds".
Hist(a) == Enc(a) \cap Est(a)
\* holders: boxed at epoch 0 or granted later
Holding == (Nodes \ Late) \cup granted
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
\* host (after an open; InOrder: in log order) or, if ~InOrder, from an
\* online co-reader peer y that holds it. A removal never reaches Withhold:
\* the host's log skips it for them.
Withheld(x, k) == x \in Withhold /\ ep[k].rem # {}
Readable(x, k) == k \notin kn[x] /\ WrapOf(k) \in sec[x] /\ ~Withheld(x, k)
FromHost(x, k) == /\ CanOpen(x) /\ k \in hostRot /\ Readable(x, k)
                  /\ InOrder => \A j \in before[k] : WrapOf(j) \in sec[x] /\ ~Withheld(x, j) => j \in kn[x]
FromPeer(x, y, k) == ~InOrder /\ y # x /\ online[y] /\ k \in kn[y] /\ Readable(x, k)

\* permissions §3: re-seal is decided "at the end of a complete sync pass of
\* the actor's labels (one that read the log of every host and peer it
\* syncs them with to its end)": the host, and every co-reader peer the node
\* has synced with (received from) that is online (R8).
HostDone(a) == /\ CanOpen(a)
               /\ \A k \in hostRot : ~Readable(a, k)
               /\ \A b \in bx : b.w \in sec[a] => b \in rd[a]
PeerDone(a, y) == \A k \in kn[y] : ~Readable(a, k)
FullPass(a) == HostDone(a) /\ \A y \in via[a] : online[y] => PeerDone(a, y)

\* permissions §3 re-seal trigger: a current holder seen without a box at a
\* current epoch, or whose heartbeat reports it stranded; only at epochs
\* established through their rotation commits (all of Est here).
Miss(a, m) == {e \in HeldCur(a) : m \notin Holders(a, e)}
ResealE(a, m) == IF Miss(a, m) # {} THEN Miss(a, m) ELSE HeldCur(a)
ResealWanted(a, m) ==
  /\ online[a] /\ m # a /\ m \in hld[a] \ dep[a] /\ FullPass(a)
  /\ Miss(a, m) # {} \/ m \in stranded

-----------------------------------------------------------------------------
Init ==
  /\ ep = [e \in Ids |-> IF e = 0
             THEN [n |-> 0, sup |-> {}, ob |-> Nodes \ Late, hist |-> {}, rem |-> {},
                   nm |-> {}, nk |-> IF Descent /\ Groups \cap (Nodes \ Late) # {} THEN {0} ELSE {},
                   ng |-> FALSE, gk |-> 0, kd |-> FALSE, fr |-> TRUE]
             ELSE [n |-> 0, sup |-> {}, ob |-> {}, hist |-> {}, rem |-> {},
                   nm |-> {}, nk |-> {}, ng |-> FALSE, gk |-> 0, kd |-> FALSE, fr |-> TRUE]]
  /\ made = {0}
  /\ kn = [x \in Nodes |-> {0}]
  /\ sec = [x \in Nodes |-> IF x \in Late THEN {} ELSE {0}]
  /\ fsec = [x \in Nodes |-> {}]
  /\ dep = [x \in Nodes |-> {}]
  /\ hld = [x \in Nodes |-> Nodes \ Late]
  /\ removed = {} /\ granted = {}
  /\ hostRot = {} /\ before = [k \in Ids |-> {}] /\ bx = {} /\ rd = [x \in Nodes |-> {}]
  /\ steps = <<[ep |-> 0, cl |-> Nodes \ Late, dr |-> FALSE]>>
  /\ inbox = {} /\ inRot = {} /\ via = [x \in Nodes |-> {}] /\ stranded = {}
  /\ enc = {} /\ leakP = FALSE
  /\ gm = {0} /\ fsup = {} /\ ks = [x \in Nodes |-> {0}]
  /\ gd = [x \in Nodes |-> FALSE] /\ gs = [x \in Nodes |-> FALSE] /\ pj = [x \in Nodes |-> {}]
  /\ rk = [x \in Nodes |-> 5]
  /\ online = [x \in Nodes |-> TRUE]
  /\ budget = [w |-> 0, off |-> 0, p |-> 0]

\* permissions §3 / crypto §4: fresh epoch n+1 superseding the current ones
\* of the rotator, boxed to every current holder it knows, history box of
\* every established secret it holds. R: the removals this commit carries
\* (commits §2: a removal and the rotation it requires are one commit).
\* permissions §3: a holder it boxes that holds no box at a current read epoch
\* before it (as the rotator knows) also gets the rotation by inbox.
\* crypto §4 names: the removals the rotator holds (its applied rotation
\* commits carrying one; OwnNames: none, the negative control), the departure
\* from the group it holds (GroupNames), and per group boxed the keyset epoch
\* its box names.
RotateR(a, R) ==
  /\ online[a] /\ Cardinality(made) <= MaxE
  /\ LET k == Cardinality(made)
         sup == Cur(a)
         d == dep[a] \cup R
         ob == hld[a] \ (d \cup (IF BoxG(a) THEN {} ELSE Groups))
     IN /\ ep' = [ep EXCEPT ![k] = [n |-> 1 + Max({ep[e].n : e \in sup}),
                    sup |-> sup, ob |-> ob, hist |-> Hist(a), rem |-> R,
                    nm |-> IF OwnNames THEN {} ELSE {j \in kn[a] : ep[j].rem # {}},
                    nk |-> IF ob \cap Groups # {} THEN (IF KeysetNames THEN {SealK(a)} ELSE {})
                           ELSE IF Descent THEN Anchors(a) ELSE {},
                    ng |-> IF Descent THEN gd[a] /\ Groups \cap hld[a] # {} /\ ob \cap Groups = {}
                           ELSE GroupNames /\ (gd[a] \/ gs[a]) /\ Groups \cap hld[a] # {},
                    gk |-> SealK(a), kd |-> gd[a] /\ ~Bound(a), fr |-> ~Bound(a)]]
        /\ made' = made \cup {k}
        /\ kn' = [kn EXCEPT ![a] = @ \cup {k}]
        /\ sec' = [sec EXCEPT ![a] = @ \cup {k}]
        /\ dep' = [dep EXCEPT ![a] = d]
        /\ removed' = removed \cup R
        /\ inRot' = inRot \cup {<<m, k>> : m \in {y \in ob \ {a} :
                                   \A e \in sup : y \notin Holders(a, e)}}
        /\ leakP' = (leakP \/ ~(Hist(a) \subseteq sec[a]))
  /\ UNCHANGED <<fsec, hld, granted, hostRot, before, bx, rd, steps, inbox, via, stranded, enc,
                 gvars, online, budget>>
Rotate(a) == RotateR(a, {})
\* A Late holder is removed only once granted, and never granted again (a
\* re-grant of a departed party is out of scope).
Remove(m) == m \in (Departing \cap Holding) \ removed /\ RotateR(Remover, {m})
\* permissions §3 / crypto §4: MUST rotate before encrypting under an epoch
\* that does not cover a known departure: a content write (pending while the
\* budget lasts) or a re-seal box (boxing is encrypting under). MAY eagerly.
RotateForced(a) ==
  /\ \/ budget.w < Writes /\ ~Covers(a, EncEp(a))
     \/ \E m \in Nodes : ResealWanted(a, m) /\ \E e \in ResealE(a, m) \cup {EncEp(a)} : ~Covers(a, e)
  /\ Rotate(a)

\* sync §5: first upload the actor's role commits it holds that the
\* host lacks (UploadRot), then register.
Register(a) ==
  /\ online[a] /\ NeedsReg(a) /\ kn[a] \ {0} \subseteq hostRot
  /\ steps' = Append(steps, [ep |-> EncEp(a), cl |-> Holders(a, EncEp(a)), dr |-> FALSE])
  /\ leakP' = (leakP \/ ~({Top.ep, EncEp(a)} \subseteq sec[a]))
  /\ UNCHANGED <<ep, made, kn, sec, fsec, dep, hld, removed, granted, hostRot, before, bx, rd,
                 inbox, inRot, via, stranded, enc, online, budget, gvars>>

\* sync §5: rotation commits go up under the head's keys (write key never
\* rotated here), before the step.
UploadRot(a, k) ==
  /\ online[a] /\ k \in kn[a] \ hostRot /\ k # 0
  \* permissions §3: a remover places the removal before any other upload.
  /\ \A j \in kn[a] \ hostRot : ep[j].rem # {} => j = k
  /\ hostRot' = hostRot \cup {k}
  /\ before' = [before EXCEPT ![k] = hostRot]
  /\ UNCHANGED <<ep, made, kn, sec, fsec, dep, hld, removed, granted, bx, rd, steps, inbox,
                 inRot, via, stranded, enc, leakP, online, budget, gvars>>

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
  \* permissions §3 Left out: a holder actor g is boxed only where BoxG; else
  \* the grant boxes nothing (GNamesBy = "grant": it is refused)
  /\ m \in Groups /\ ~BoxG(a) => Frozen /\ GNamesBy = "current"
  /\ granted' = granted \cup {m}
  /\ hld' = [hld EXCEPT ![a] = @ \cup {m}]
  /\ rk' = IF m \in Groups THEN [rk EXCEPT ![a] = SealK(a)] ELSE rk
  /\ PlaceBox(a, [m |-> m, eps |-> IF m \in Groups /\ ~BoxG(a) THEN {} ELSE HeldCur(a),
                  w |-> EncEp(a), g |-> TRUE, gk |-> SealK(a), kn |-> gd[a],
                  kd |-> GrantNames /\ gd[a] /\ ~Bound(a), fr |-> ~Bound(a)])
  /\ UNCHANGED <<ep, made, kn, sec, fsec, dep, removed, hostRot, before, steps, inRot, via,
                 stranded, enc, online, budget, gm, fsup, ks, gd, gs, pj>>

\* Reading a grant or re-seal commit from the label: a grant teaches the
\* holder; the boxed holder itself takes the secrets and history boxes.
RecvBox(x, b) ==
  /\ online[x] /\ CanOpen(x) /\ b \in bx \ rd[x] /\ b.w \in sec[x]
  /\ rd' = [rd EXCEPT ![x] = @ \cup {b}]
  /\ hld' = IF b.g THEN [hld EXCEPT ![x] = @ \cup {b.m}] ELSE hld
  /\ rk' = IF b.g /\ b.m \in Groups THEN [rk EXCEPT ![x] = b.gk] ELSE rk
  /\ sec' = IF b.m = x THEN [sec EXCEPT ![x] = @ \cup b.eps \cup UNION {ep[e].hist : e \in b.eps}]
            ELSE sec
  /\ UNCHANGED <<ep, made, kn, fsec, dep, removed, granted, hostRot, before, bx, steps,
                 inbox, inRot, via, stranded, enc, leakP, online, budget, gm, fsup, ks, gd, gs, pj>>

\* crypto §4: never encrypt under an epoch that does not cover a known
\* departure; crypto §5: a node holding no current secret writes nothing.
WriteContent(a) ==
  /\ online[a] /\ budget.w < Writes /\ ~NeedsReg(a) /\ HeldCur(a) # {}
  /\ Covers(a, EncEp(a))
  /\ enc' = enc \cup {<<EncEp(a), dep[a], gd[a]>>}
  /\ leakP' = (leakP \/ EncEp(a) \notin sec[a])
  /\ budget' = [budget EXCEPT !.w = @ + 1]
  /\ UNCHANGED <<ep, made, kn, sec, fsec, dep, hld, removed, granted, hostRot, before, bx, rd,
                 steps, inbox, inRot, via, stranded, online, gvars>>

\* A box for x gives the new secret and, by the history box, every secret the
\* rotator held; the removals it carries become known.
Apply(x, k) ==
  /\ kn' = [kn EXCEPT ![x] = @ \cup {k}]
  /\ sec' = [sec EXCEPT ![x] = @ \cup (IF x \in ep[k].ob THEN {k} \cup ep[k].hist ELSE {})]
  /\ dep' = [dep EXCEPT ![x] = @ \cup ep[k].rem]
RecvHost(x, k) ==
  /\ online[x] /\ FromHost(x, k) /\ Apply(x, k)
  /\ UNCHANGED <<ep, made, fsec, hld, removed, granted, hostRot, before, bx, rd, steps, inbox,
                 inRot, via, stranded, enc, leakP, online, budget, gvars>>
RecvPeer(x, y, k) ==
  /\ online[x] /\ FromPeer(x, y, k) /\ Apply(x, k)
  /\ via' = [via EXCEPT ![x] = @ \cup {y}]
  /\ UNCHANGED <<ep, made, fsec, hld, removed, granted, hostRot, before, bx, rd, steps, inbox,
                 inRot, stranded, enc, leakP, online, budget, gvars>>
\* permissions §3: a rotation delivered by inbox (no label access needed).
InboxRot(x, k) ==
  /\ online[x] /\ <<x, k>> \in inRot /\ ~Withheld(x, k) /\ Apply(x, k)
  /\ inRot' = inRot \ {<<x, k>>}
  /\ UNCHANGED <<ep, made, fsec, hld, removed, granted, hostRot, before, bx, rd, steps, inbox,
                 via, stranded, enc, leakP, online, budget, gvars>>
Recv(x, k) == RecvHost(x, k) \/ \E y \in Nodes : RecvPeer(x, y, k)

\* permissions §3: SHOULD re-seal (treated as done: fair), with the epochs'
\* history boxes, delivered by inbox and placed under the actor's labels like
\* any role commit (wrapped under the newest epoch); boxing and that
\* wrap are encrypting under, so only at epochs covering every departure the
\* re-sealer knows.
Reseal(a, m) ==
  /\ ResealWanted(a, m) /\ HeldCur(a) # {}
  /\ \A e \in ResealE(a, m) \cup {EncEp(a)} : Covers(a, e)
  /\ m \in Groups => BoxG(a)
  /\ PlaceBox(a, [m |-> m, eps |-> ResealE(a, m), w |-> EncEp(a), g |-> FALSE, gk |-> SealK(a),
                  kn |-> gd[a], kd |-> GrantNames /\ gd[a] /\ ~Bound(a), fr |-> ~Bound(a)])
  /\ stranded' = stranded \ {m}
  /\ UNCHANGED <<ep, made, kn, sec, fsec, dep, hld, removed, granted, hostRot, before, steps,
                 inRot, via, enc, online, budget, gvars>>

\* crypto §4: the grant or re-seal re-writes each boxed epoch's history box.
InboxRecv(m, e) ==
  /\ online[m] /\ <<m, e>> \in inbox
  /\ sec' = [sec EXCEPT ![m] = @ \cup {e} \cup ep[e].hist]
  /\ inbox' = inbox \ {<<m, e>>}
  /\ UNCHANGED <<ep, made, kn, fsec, dep, hld, removed, granted, hostRot, before, bx, rd, steps,
                 inRot, via, stranded, enc, leakP, online, budget, gvars>>

\* Adversary (crypto §4): anyone can seal a box to a holder's keys.0 in a
\* commit that stays pending or is invalid, naming an existing epoch with a
\* secret of its choosing; the holder keeps it for reading only (fsec).
Plant(x, e) ==
  /\ budget.p < Plants /\ e \in made /\ e \notin sec[x] \cup fsec[x]
  /\ fsec' = [fsec EXCEPT ![x] = @ \cup {e}]
  /\ budget' = [budget EXCEPT !.p = @ + 1]
  /\ UNCHANGED <<ep, made, kn, sec, dep, hld, removed, granted, hostRot, before, bx, rd, steps,
                 inbox, inRot, via, stranded, enc, leakP, online, gvars>>

\* permissions §4: MUST place a stranded heartbeat when it cannot read the
\* current epoch: it reached the head and after a complete pass there cannot
\* open the epoch it registers, or a claim on the way was refused. By deposit
\* (no open needed), wrapped under the newest established held secret;
\* refused if the deposit seed was refreshed by a rotation whose keys.0 the
\* node has not read (crypto §3).
Heartbeat(x) ==
  /\ online[x] /\ x \in Holding /\ x \notin stranded /\ x \notin dep[x]
  /\ \/ CanOpen(x) /\ Top.ep \notin sec[x] /\ ~\E k \in hostRot : FromHost(x, k)
     \/ ~CanOpen(x)
  /\ Refresh => Top.ep \in kn[x]
  /\ Enc(x) \cap Est(x) # {}
  /\ stranded' = stranded \cup {x}
  /\ leakP' = (leakP \/ NewestOf(Enc(x) \cap Est(x)) \notin sec[x])
  /\ UNCHANGED <<ep, made, kn, sec, fsec, dep, hld, removed, granted, hostRot, before, bx, rd,
                 steps, inbox, inRot, via, enc, online, budget, gvars>>

\* sync §4: a superseded step's claim set is kept ROLE_KEEP, then may go.
Drop(i) ==
  /\ DropClaims /\ i < Len(steps) /\ ~steps[i].dr
  /\ steps' = [steps EXCEPT ![i].dr = TRUE]
  /\ UNCHANGED <<ep, made, kn, sec, fsec, dep, hld, removed, granted, hostRot, before, bx, rd,
                 inbox, inRot, via, stranded, enc, leakP, online, budget, gvars>>

\* Device d, an admin of group g, leaves it (R_P): g's admin (outside this
\* model) rotates its keyset to epoch 1, which d does not hold; R_P carries
\* the departure. Unfair, once.
GLeave == /\ Groups # {} /\ gm = {0} /\ gm' = {0, 1}
          /\ UNCHANGED <<fsup, ks, gd, gs, pj, rk>>
\* g's admin rotates it again (keyset 2, listing 0 and 1; carries no
\* departure of d). Unfair, once.
GRot == /\ "rot" \in GActs /\ 1 \in gm /\ 2 \notin gm /\ gm' = gm \cup {2}
        /\ UNCHANGED <<fsup, ks, gd, gs, pj, rk>>
\* d, removed, writes keyset 3 (its own KEM keys) listing every keyset made
\* as superseded: their epochs are public. Unfair, once.
Forge == /\ "forge" \in GActs /\ 1 \in gm /\ 3 \notin gm
         /\ gm' = gm \cup {3} /\ fsup' = gm
         /\ UNCHANGED <<ks, gd, gs, pj, rk>>
\* x, a node R_P is withheld from, gets a roster snapshot of g made after R_P
\* (an epoch start). Unfair.
GSnap(x) == /\ "snap" \in GActs /\ 1 \in gm /\ ~gs[x] /\ gs' = [gs EXCEPT ![x] = TRUE]
            /\ UNCHANGED <<gm, fsup, ks, gd, pj, rk>>
\* Admin x reads a keyset body of g (published under the labels of what g
\* holds); R_P never reaches Withhold. Keyset 1 comes in R_P, with the departure.
LearnK(x, k) == /\ k \in gm /\ k \notin ks[x] /\ ~(k = 1 /\ x \in Withhold /\ ~Split)
                /\ ks' = [ks EXCEPT ![x] = @ \cup {k}]
                /\ gd' = IF k = 1 /\ ~Split THEN [gd EXCEPT ![x] = TRUE] ELSE gd
                /\ UNCHANGED <<gm, fsup, gs, pj, rk>>
\* Split: R_P's roles.0 part (the departure) reaches x apart from its keys.0
\* part (body 1), in any order; never Withhold.
LearnRP(x) == /\ Split /\ 1 \in gm /\ ~gd[x] /\ x \notin Withhold
              /\ gd' = [gd EXCEPT ![x] = TRUE]
              /\ UNCHANGED <<gm, fsup, ks, gs, pj, rk>>
\* An admin of g that has not seen R_P rotates g from keyset 0: an honest fork
\* 4 of 1 (one n), boxing d; written later, it wins keys.0's LWW. Unfair, once.
GFork == /\ "fork" \in GActs /\ 1 \in gm /\ 4 \notin gm /\ gm' = gm \cup {4}
         /\ UNCHANGED <<fsup, ks, gd, gs, pj, rk>>
\* A grant of g reaches admin x as its edge alone (a certificate copy; its
\* boxes deposited under the label and never received): x knows g a holder.
\* Unfair.
LearnEdge(x, b) ==
  /\ Proj # "none" /\ b \in bx /\ b.g /\ b.m \in Groups /\ b \notin rd[x] \cup pj[x]
  /\ pj' = [pj EXCEPT ![x] = @ \cup {b}]
  /\ hld' = [hld EXCEPT ![x] = @ \cup {b.m}]
  /\ rk' = [rk EXCEPT ![x] = b.gk]
  /\ UNCHANGED <<ep, made, kn, sec, fsec, dep, removed, granted, hostRot, before, bx, rd, steps,
                 inbox, inRot, via, stranded, enc, leakP, online, budget, gm, fsup, ks, gd, gs>>
\* A second edge write of g on A naming a keyset nobody holds (an invite
\* holder's grant whose deposit never lands) reaches x and stands: x, holding
\* no box to g carrying names, is bound to it and leaves g out until a free
\* sealer's box reaches it (crypto §4). Unfair, once per node.
BadEdge(x) == /\ "badedge" \in GActs /\ Groups \cap hld[x] # {} /\ rk[x] # 5
              /\ rk' = [rk EXCEPT ![x] = 5]
              /\ UNCHANGED <<gm, fsup, ks, gd, gs, pj>>
GOthers == UNCHANGED <<ep, made, kn, sec, fsec, dep, hld, removed, granted, hostRot, before, bx,
                      rd, steps, inbox, inRot, via, stranded, enc, leakP, online, budget>>
GStep == /\ \/ GLeave \/ GRot \/ Forge \/ GFork \/ \E x \in Withhold : GSnap(x) \/ BadEdge(x)
            \/ \E x \in Admins : LearnRP(x) \/ \E k \in 0..4 : LearnK(x, k)
         /\ GOthers

GoOff(x) == /\ online[x] /\ budget.off < Offs
            /\ online' = [online EXCEPT ![x] = FALSE] /\ budget' = [budget EXCEPT !.off = @ + 1]
            /\ UNCHANGED <<ep, made, kn, sec, fsec, dep, hld, removed, granted, hostRot, before,
                           bx, rd, steps, inbox, inRot, via, stranded, enc, leakP, gvars>>
GoOn(x) == /\ ~online[x] /\ online' = [online EXCEPT ![x] = TRUE]
           /\ UNCHANGED <<ep, made, kn, sec, fsec, dep, hld, removed, granted, hostRot, before,
                          bx, rd, steps, inbox, inRot, via, stranded, enc, leakP, budget, gvars>>

Next ==
  \/ \E a \in Admins : Rotate(a) \/ Register(a) \/ WriteContent(a)
                       \/ (\E k \in Ids : UploadRot(a, k))
                       \/ (\E m \in Nodes : Reseal(a, m) \/ Grant(a, m))
  \/ \E m \in Departing : Remove(m)
  \/ \E x \in Nodes : \/ Heartbeat(x) \/ GoOff(x) \/ GoOn(x)
                      \/ (\E k \in Ids : Recv(x, k) \/ InboxRecv(x, k) \/ InboxRot(x, k)
                                         \/ Plant(x, k))
                      \/ (\E b \in bx : RecvBox(x, b))
  \/ \E x \in Admins : \E b \in bx : LearnEdge(x, b)
  \/ \E i \in 1..Len(steps) : Drop(i)
  \/ GStep

\* Weak fairness of honest steps; eager rotation, removal, grants, writes,
\* claim-set drops, going offline and planting are unfair.
Fairness ==
  /\ \A a \in Admins : /\ WF_vars(RotateForced(a)) /\ WF_vars(Register(a))
                       /\ \A k \in Ids : WF_vars(UploadRot(a, k))
                       /\ \A m \in Nodes : WF_vars(Reseal(a, m))
                       /\ \A k \in 0..4 : WF_vars(LearnK(a, k) /\ GOthers)
                       /\ WF_vars(LearnRP(a) /\ GOthers)
  /\ \A x \in Nodes : /\ WF_vars(Heartbeat(x)) /\ WF_vars(GoOn(x))
                      /\ \A k \in Ids : /\ WF_vars(Recv(x, k)) /\ WF_vars(InboxRecv(x, k))
                                       /\ WF_vars(InboxRot(x, k))
                      /\ WF_vars(\E b \in bx : RecvBox(x, b))

Spec == Init /\ [][Next]_vars /\ Fairness

-----------------------------------------------------------------------------
GCur == {e \in made : ~\E f \in made : e \in ep[f].sup}

TypeOK == /\ made \subseteq Ids /\ removed \subseteq Departing /\ granted \subseteq Late
          /\ Groups \subseteq Readers /\ Withhold \subseteq Admins
          /\ gm \subseteq 0..4 /\ \A x \in Nodes : ks[x] \subseteq gm /\ rk[x] \in 0..5
          /\ \A x \in Nodes : sec[x] \subseteq made /\ kn[x] \subseteq made
                              /\ fsec[x] \subseteq made /\ via[x] \subseteq Nodes
                              /\ rd[x] \subseteq bx

\* crypto §4 covers rule, its purpose: content a writer encrypted while it
\* knew of M's departure is never readable by M.
NoLeak == \A c \in enc : \A m \in c[2] : c[1] \notin sec[m]
\* permissions §3 "requires rotating every role secret M could open": a
\* departed holder never holds an epoch whose rotation did not box it.
DepartedLocked == \A m \in removed : \A e \in sec[m] : m \in ep[e].ob
\* The epochs device d opens after leaving its group: those boxed to the group
\* at keyset epoch 0, 3 or 4 (by a rotation, grant or re-seal), with their
\* history.
DevBoxed == {e \in made : ep[e].ob \cap Groups # {} /\ ep[e].gk \in {0, 3, 4}}
            \cup UNION {b.eps : b \in {c \in bx : c.m \in Groups /\ c.gk \in {0, 3, 4}}}
DevSec == UNION {{e} \cup ep[e].hist : e \in DevBoxed}
\* permissions §3 for a departure inside a holder (crypto §4 covers rule):
\* d never opens an epoch whose rotator knew d left (held R_P).
DevLocked == \A e \in DevSec : ~ep[e].kd
\* ... nor content written while its writer knew d left.
DevNoLeak == \A c \in enc : c[3] => c[1] \notin DevSec
\* With g granted once (Late), by a granter that knew d left: d, gone from g
\* before g held a role on A, opens no secret of A at all (the study's NoLeak,
\* second half).
DevGranted == (\E b \in bx : b.g /\ b.m \in Groups /\ b.kn) => DevSec = {}

\* crypto §4: a secret from a planted box (a non-holder's pending or invalid
\* commit) never becomes an encrypting key: nothing was wrapped, boxed,
\* history-boxed or signed under it.
NoPlantedKey == ~leakP

\* permissions §3 / sync §5: every current holder eventually opens every
\* current epoch (by claims, downloads or re-seal) ...
CurrentOpens == <>[](\A x \in Holding \ removed : GCur \subseteq sec[x])
\* ... and reads the label: every epoch content was written under (for a
\* grantee, older epochs by the history box, crypto §4).
ReadsAll == <>[](\A x \in Holding \ removed : \A c \in enc : c[1] \in sec[x])
=============================================================================
