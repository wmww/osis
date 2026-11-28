------------------------------- MODULE Rotation -------------------------------
(* Read-role rotation, removals, grants, sync ID registration steps, claims and *)
(* re-seal for one actor whose sync ID sits at one store (spec/crypto.md         *)
(* §3-§5, spec/sync-ids.md §2, spec/sync-ids.md §6, spec/permissions.md §3-§4, commits §2).      *)
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
          Offs,       \* offline transitions in a run
          Plants,     \* adversary: boxes planted by a non-holder in a run
          InOrder,    \* TRUE: one source, the store's log order (cursor sync);
                      \* FALSE: any order, and co-reader peers serve rotations
          Withhold,   \* admins the store and peers withhold every removal
                      \* from, forever
          NoBoxCovers, \* TRUE: negative control, a holder with no box at e
                      \* counts as covered
          GrantClaims \* FALSE: negative control, a grant or re-seal carries
                      \* no claim (claims from rotation commits alone)

Nodes == Admins \cup Readers
Ids == 0..MaxE
Max(S) == CHOOSE x \in S : \A y \in S : x >= y

VARIABLES ep,       \* ep[e] = [n, sup, ob, hist, rem, nm]; ob = holders the
                    \* rotation boxed; rem = removals the rotation commit carries;
                    \* nm = the rotation commits carrying one its rotator held
          made,     \* created epoch ids
          kn,       \* kn[x]: rotation commits x holds (0 always)
          sec,      \* sec[x]: epoch secrets x holds from applied valid boxes
          fsec,     \* fsec[x]: secrets x learned only from a planted box
          dep,      \* dep[x]: departures x knows of
          hld,      \* hld[x]: holders x knows were granted
          removed,  \* departures that happened
          granted,  \* Late holders granted so far
          storeRot,  \* rotation commits at the store
          before,   \* before[k]: rotations logged before rotation k's logging
          bx,       \* grant and re-seal commits under the sync ID:
                    \* [m: holder boxed, eps: epochs boxed, w: wrap epoch, g: grant]
          rd,       \* rd[x]: the commits of bx that x has read
          steps,    \* registration path: <<[ep]>>
          sealed,   \* grant and re-seal boxes the holder takes by its claim
                    \* (its W carries the commit's blob key): <<holder, epoch>>
          sealedRot, \* rotations taken so: <<holder, rotation>>
          via,      \* via[x]: co-reader peers x received rotation commits from
          stranded, \* holders whose stranded notice is under the sync ID
          enc,      \* content written: <<epoch, departures the writer knew>>
          leakP,    \* TRUE once something was encrypted under a planted secret
          online, budget
vars == <<ep, made, kn, sec, fsec, dep, hld, removed, granted, storeRot, before, bx, rd,
          steps, sealed, sealedRot, via, stranded, enc, leakP, online, budget>>

ep_n(e) == ep[e].n
\* crypto §4: newest = greatest n, ties by lowest nonce (here: lowest id).
Newer(e, f) == ep_n(e) > ep_n(f) \/ (ep_n(e) = ep_n(f) /\ e < f)
NewestOf(S) == CHOOSE e \in S : \A f \in S \ {e} : Newer(e, f)
\* crypto §4: "A secret learned only from a pending or invalid commit is kept
\* for reading and never encrypted under until an applied valid box carries
\* it." Enc(x) is what x may encrypt under: secrets from applied valid boxes
\* only, never fsec (README: negative control with sec[x] \cup fsec[x]).
Enc(x) == sec[x]
\* crypto §4: an epoch is established at x when x applied its rotation commit
\* and, if x holds its secret, its names are met: x holds every removal its
\* rotator held (ep[i].nm, rotation commits; the commit itself carries its own:
\* the departs mark). Own rotations are in kn at once; no rotation commit is
\* invalid; the actor has no secrets.0 snapshots (ASSUMPTIONS.md). Epoch 0
\* is the derived epoch.
Est(x) == {0} \cup {i \in kn[x] : i \notin Enc(x) \/ ep[i].nm \subseteq kn[x]}
\* crypto §4: current = established, and no established rotation supersedes it.
Cur(x) == LET E == Est(x) IN {e \in E : ~\E f \in E : e \in ep[f].sup}
HeldCur(x) == Cur(x) \cap Enc(x)
\* crypto §5: a node logging an entry wraps under the newest current read epoch whose
\* secret it holds; a node holding none uses the newest established secret it
\* holds (its stranded notice only). crypto §4: established epochs only.
EncEp(x) == NewestOf(IF HeldCur(x) # {} THEN HeldCur(x) ELSE Enc(x) \cap Est(x))
\* The boxes x knows of: those of the rotation commits it applied and of the
\* grant and re-seal commits it read (permissions §3: a re-seal goes under
\* the actor's sync IDs, so every node learns its boxes).
Holders(x, e) == (IF e \in kn[x] THEN ep[e].ob ELSE {})
                 \cup {b.m : b \in {c \in rd[x] : e \in c.eps}}
\* Frozen coverage (notes/keys-coverage.md, Frozen coverage): e covers exactly
\* the departures its names name: the removals carried by the rotation
\* commits its rotator held (nm) and by itself (the departs mark). Boxes
\* decide nothing (NoBoxCovers: a box-less holder covered, a negative control).
NamedRem(e) == UNION {ep[j].rem : j \in ep[e].nm} \cup ep[e].rem
Covers(x, e) ==
  \A m \in dep[x] : m \in NamedRem(e) \/ (NoBoxCovers /\ m \notin Holders(x, e))
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
\* sync-ids §3 claims: the claims bound to epoch e at the store are those of
\* the holders boxed at e by the commits it holds (the rotation commit making e,
\* each grant and re-seal boxing e); never dropped.
Claims(e) == (IF e = 0 \/ e \in storeRot THEN ep[e].ob ELSE {})
             \cup (IF GrantClaims THEN {b.m : b \in {c \in bx : e \in c.eps}} ELSE {})
\* sync-opens §4, the one open rule: the sync proof of a step on the path
\* (the head's whole, an older one's up to that step's end, which serves the
\* rotations superseding it: abstracted, ASSUMPTIONS.md) or a head claim key.
\* Opening is not encrypting under (crypto §4): any held secret opens.
CanOpen(x) ==
  \/ \E j \in 1..Len(steps) : steps[j].ep \in sec[x]
  \/ x \in Claims(Top.ep)

\* Download of rotation commit k: readable under its wrap epoch. From the
\* store (after an open; InOrder: in log order) or, if ~InOrder, from an
\* online co-reader peer y that holds it. A removal never reaches Withhold:
\* the store's log skips it for them.
Withheld(x, k) == x \in Withhold /\ ep[k].rem # {}
Readable(x, k) == k \notin kn[x] /\ WrapOf(k) \in sec[x] /\ ~Withheld(x, k)
FromStore(x, k) == /\ CanOpen(x) /\ k \in storeRot /\ Readable(x, k)
                   /\ InOrder => \A j \in before[k] : WrapOf(j) \in sec[x] /\ ~Withheld(x, j) => j \in kn[x]
FromPeer(x, y, k) == ~InOrder /\ y # x /\ online[y] /\ k \in kn[y] /\ Readable(x, k)

\* permissions §3: re-seal is decided "at the end of a complete sync pass of
\* the actor's sync IDs (one that read the log of every store and peer it
\* syncs them with to its end)": the store, and every co-reader peer the node
\* has synced with (received from) that is online (R8).
StoreDone(a) == /\ CanOpen(a)
                /\ \A k \in storeRot : ~Readable(a, k)
                /\ \A b \in bx : b.w \in sec[a] => b \in rd[a]
PeerDone(a, y) == \A k \in kn[y] : ~Readable(a, k)
FullPass(a) == StoreDone(a) /\ \A y \in via[a] : online[y] => PeerDone(a, y)

\* permissions §3 re-seal trigger: a current holder seen without a box at a
\* current epoch, or whose notice reports it stranded; only at epochs
\* established through their rotation commits (all of Est here).
Miss(a, m) == {e \in HeldCur(a) : m \notin Holders(a, e)}
ResealE(a, m) == IF Miss(a, m) # {} THEN Miss(a, m) ELSE HeldCur(a)
ResealWanted(a, m) ==
  /\ online[a] /\ m # a /\ m \in hld[a] \ dep[a] /\ FullPass(a)
  /\ Miss(a, m) # {} \/ m \in stranded

-----------------------------------------------------------------------------
Init ==
  /\ ep = [e \in Ids |-> IF e = 0
             THEN [n |-> 0, sup |-> {}, ob |-> Nodes \ Late, hist |-> {}, rem |-> {}, nm |-> {}]
             ELSE [n |-> 0, sup |-> {}, ob |-> {}, hist |-> {}, rem |-> {}, nm |-> {}]]
  /\ made = {0}
  /\ kn = [x \in Nodes |-> {0}]
  /\ sec = [x \in Nodes |-> IF x \in Late THEN {} ELSE {0}]
  /\ fsec = [x \in Nodes |-> {}]
  /\ dep = [x \in Nodes |-> {}]
  /\ hld = [x \in Nodes |-> Nodes \ Late]
  /\ removed = {} /\ granted = {}
  /\ storeRot = {} /\ before = [k \in Ids |-> {}] /\ bx = {} /\ rd = [x \in Nodes |-> {}]
  /\ steps = <<[ep |-> 0]>>
  /\ sealed = {} /\ sealedRot = {} /\ via = [x \in Nodes |-> {}] /\ stranded = {}
  /\ enc = {} /\ leakP = FALSE
  /\ online = [x \in Nodes |-> TRUE]
  /\ budget = [w |-> 0, off |-> 0, p |-> 0]

\* permissions §3 / crypto §4: fresh epoch n+1 superseding the current ones
\* of the rotator, boxed to every current holder it knows, history box of
\* every established secret it holds. R: the removals this commit carries
\* (commits §2: a removal and the rotation it requires are one commit).
\* permissions §3: a holder it boxes that holds no box at a current read epoch
\* before it (as the rotator knows) also opens the rotation: by its claim,
\* whose W carries the blob key (spec/sync-ids.md §3).
\* crypto §4 names: the removals the rotator holds (its applied rotation
\* commits carrying one).
RotateR(a, R) ==
  /\ online[a] /\ Cardinality(made) <= MaxE
  /\ LET k == Cardinality(made)
         sup == Cur(a)
         d == dep[a] \cup R
         ob == hld[a] \ d
     IN /\ ep' = [ep EXCEPT ![k] = [n |-> 1 + Max({ep[e].n : e \in sup}),
                    sup |-> sup, ob |-> ob, hist |-> Hist(a), rem |-> R,
                    nm |-> {j \in kn[a] : ep[j].rem # {}}]]
        /\ made' = made \cup {k}
        /\ kn' = [kn EXCEPT ![a] = @ \cup {k}]
        /\ sec' = [sec EXCEPT ![a] = @ \cup {k}]
        /\ dep' = [dep EXCEPT ![a] = d]
        /\ removed' = removed \cup R
        /\ sealedRot' = sealedRot \cup {<<m, k>> : m \in {y \in ob \ {a} :
                                   \A e \in sup : y \notin Holders(a, e)}}
        /\ leakP' = (leakP \/ ~(Hist(a) \subseteq sec[a]))
  /\ UNCHANGED <<fsec, hld, granted, storeRot, before, bx, rd, steps, sealed, via, stranded, enc,
                 online, budget>>
Rotate(a) == RotateR(a, {})
\* A Late holder is removed only once granted, and never granted again (a
\* re-grant of a departed party is out of scope).
Remove(m) == m \in (Departing \cap Holding) \ removed /\ RotateR(Remover, {m})
\* permissions §3 / crypto §4: MUST rotate before encrypting under an epoch
\* that does not cover a known departure: a content write (pending while the
\* budget lasts) or a re-seal box (this model re-seals only at covering
\* epochs; Depth0 CarryFree re-seals at blocked ones). MAY eagerly.
RotateForced(a) ==
  /\ \/ budget.w < Writes /\ ~Covers(a, EncEp(a))
     \/ \E m \in Nodes : ResealWanted(a, m) /\ \E e \in ResealE(a, m) \cup {EncEp(a)} : ~Covers(a, e)
  /\ Rotate(a)

\* sync §5: first log the actor's role commits it holds that the
\* store lacks (LogRot), then register.
Register(a) ==
  /\ online[a] /\ NeedsReg(a) /\ kn[a] \ {0} \subseteq storeRot
  /\ steps' = Append(steps, [ep |-> EncEp(a)])
  /\ leakP' = (leakP \/ ~({Top.ep, EncEp(a)} \subseteq sec[a]))
  /\ UNCHANGED <<ep, made, kn, sec, fsec, dep, hld, removed, granted, storeRot, before, bx, rd,
                 sealed, sealedRot, via, stranded, enc, online, budget>>

\* sync §5: rotation commits go up under the head's keys (write key never
\* rotated here), before the step.
LogRot(a, k) ==
  /\ online[a] /\ k \in kn[a] \ storeRot /\ k # 0
  \* permissions §3: a remover logs the removal before any other logging.
  /\ \A j \in kn[a] \ storeRot : ep[j].rem # {} => j = k
  /\ storeRot' = storeRot \cup {k}
  /\ before' = [before EXCEPT ![k] = storeRot]
  /\ UNCHANGED <<ep, made, kn, sec, fsec, dep, hld, removed, granted, bx, rd, steps, sealed,
                 sealedRot, via, stranded, enc, leakP, online, budget>>

\* A grant or re-seal commit b by a: logged under the sync ID (wrapped under a's
\* newest epoch), read by a at once, b.m's claim carrying its blob key.
LogBox(a, b) ==
  /\ bx' = bx \cup {b}
  /\ rd' = [rd EXCEPT ![a] = @ \cup {b}]
  /\ sealed' = sealed \cup {<<b.m, e>> : e \in b.eps}
  /\ leakP' = (leakP \/ ~(b.eps \cup {b.w} \subseteq sec[a]))

\* crypto §4: a grant writes the grantee's boxes at each current epoch (with
\* their history boxes), its claim carrying the commit's blob key; the grant commit goes under the
\* sync ID wrapped under the granter's newest epoch. Unfair (a choice).
Grant(a, m) ==
  /\ online[a] /\ m \in Late \ granted /\ ~NeedsReg(a) /\ HeldCur(a) # {}
  /\ \A e \in HeldCur(a) : Covers(a, e)
  /\ granted' = granted \cup {m}
  /\ hld' = [hld EXCEPT ![a] = @ \cup {m}]
  /\ LogBox(a, [m |-> m, eps |-> HeldCur(a), w |-> EncEp(a), g |-> TRUE])
  /\ UNCHANGED <<ep, made, kn, sec, fsec, dep, removed, storeRot, before, steps, sealedRot, via,
                 stranded, enc, online, budget>>

\* Reading a grant or re-seal commit from the sync ID: a grant teaches the
\* holder; the boxed holder itself takes the secrets and history boxes.
RecvBox(x, b) ==
  /\ online[x] /\ CanOpen(x) /\ b \in bx \ rd[x] /\ b.w \in sec[x]
  /\ rd' = [rd EXCEPT ![x] = @ \cup {b}]
  /\ hld' = IF b.g THEN [hld EXCEPT ![x] = @ \cup {b.m}] ELSE hld
  /\ sec' = IF b.m = x THEN [sec EXCEPT ![x] = @ \cup b.eps \cup UNION {ep[e].hist : e \in b.eps}]
            ELSE sec
  /\ UNCHANGED <<ep, made, kn, fsec, dep, removed, granted, storeRot, before, bx, steps,
                 sealed, sealedRot, via, stranded, enc, leakP, online, budget>>

\* crypto §4: never encrypt under an epoch that does not cover a known
\* departure; crypto §5: a node holding no current secret writes nothing.
WriteContent(a) ==
  /\ online[a] /\ budget.w < Writes /\ ~NeedsReg(a) /\ HeldCur(a) # {}
  /\ Covers(a, EncEp(a))
  /\ enc' = enc \cup {<<EncEp(a), dep[a]>>}
  /\ leakP' = (leakP \/ EncEp(a) \notin sec[a])
  /\ budget' = [budget EXCEPT !.w = @ + 1]
  /\ UNCHANGED <<ep, made, kn, sec, fsec, dep, hld, removed, granted, storeRot, before, bx, rd,
                 steps, sealed, sealedRot, via, stranded, online>>

\* A box for x gives the new secret and, by the history box, every secret the
\* rotator held; the removals it carries become known.
Apply(x, k) ==
  /\ kn' = [kn EXCEPT ![x] = @ \cup {k}]
  /\ sec' = [sec EXCEPT ![x] = @ \cup (IF x \in ep[k].ob THEN {k} \cup ep[k].hist ELSE {})]
  /\ dep' = [dep EXCEPT ![x] = @ \cup ep[k].rem]
RecvStore(x, k) ==
  /\ online[x] /\ FromStore(x, k) /\ Apply(x, k)
  /\ UNCHANGED <<ep, made, fsec, hld, removed, granted, storeRot, before, bx, rd, steps, sealed,
                 sealedRot, via, stranded, enc, leakP, online, budget>>
RecvPeer(x, y, k) ==
  /\ online[x] /\ FromPeer(x, y, k) /\ Apply(x, k)
  /\ via' = [via EXCEPT ![x] = @ \cup {y}]
  /\ UNCHANGED <<ep, made, fsec, hld, removed, granted, storeRot, before, bx, rd, steps, sealed,
                 sealedRot, stranded, enc, leakP, online, budget>>
\* spec/sync-ids.md §3 Taking a claim: a holder that cannot open a rotation by
\* its wrap opens it by its claim, pulled once it opens S (nothing kept with the
\* holder).
TakeSealedRot(x, k) ==
  /\ online[x] /\ CanOpen(x) /\ <<x, k>> \in sealedRot /\ ~Withheld(x, k) /\ Apply(x, k)
  /\ sealedRot' = sealedRot \ {<<x, k>>}
  /\ UNCHANGED <<ep, made, fsec, hld, removed, granted, storeRot, before, bx, rd, steps, sealed,
                 via, stranded, enc, leakP, online, budget>>
Recv(x, k) == RecvStore(x, k) \/ \E y \in Nodes : RecvPeer(x, y, k)

\* permissions §3: SHOULD re-seal (treated as done: fair), with the epochs'
\* history boxes, its blob key sealed to the holder, and logged under the actor's sync IDs like
\* any role commit (wrapped under the newest epoch); boxing and that
\* wrap are encrypting under, so only at epochs covering every departure the
\* re-sealer knows.
Reseal(a, m) ==
  /\ ResealWanted(a, m) /\ HeldCur(a) # {}
  /\ \A e \in ResealE(a, m) \cup {EncEp(a)} : Covers(a, e)
  /\ LogBox(a, [m |-> m, eps |-> ResealE(a, m), w |-> EncEp(a), g |-> FALSE])
  /\ stranded' = stranded \ {m}
  /\ UNCHANGED <<ep, made, kn, sec, fsec, dep, hld, removed, granted, storeRot, before, steps,
                 sealedRot, via, enc, online, budget>>

\* crypto §4: the grant or re-seal re-writes each boxed epoch's history box;
\* the holder takes it by its claim once it opens S (spec/sync-ids.md §3).
TakeSealed(m, e) ==
  /\ online[m] /\ CanOpen(m) /\ <<m, e>> \in sealed
  /\ sec' = [sec EXCEPT ![m] = @ \cup {e} \cup ep[e].hist]
  /\ sealed' = sealed \ {<<m, e>>}
  /\ UNCHANGED <<ep, made, kn, fsec, dep, hld, removed, granted, storeRot, before, bx, rd, steps,
                 sealedRot, via, stranded, enc, leakP, online, budget>>

\* Adversary (crypto §4): anyone can seal a box to a holder's keys.0 in a
\* commit that stays pending or is invalid, naming an existing epoch with a
\* secret of its choosing; the holder keeps it for reading only (fsec).
Plant(x, e) ==
  /\ budget.p < Plants /\ e \in made /\ e \notin sec[x] \cup fsec[x]
  /\ fsec' = [fsec EXCEPT ![x] = @ \cup {e}]
  /\ budget' = [budget EXCEPT !.p = @ + 1]
  /\ UNCHANGED <<ep, made, kn, sec, dep, hld, removed, granted, storeRot, before, bx, rd, steps,
                 sealed, sealedRot, via, stranded, enc, leakP, online>>

\* permissions §4: MUST fire a stranded notice when it cannot read the
\* current epoch: it reached the head and after a complete pass there cannot
\* open the epoch it registers, or it cannot open at all. By deposit
\* (no open needed), wrapped under the newest established held secret.
\* Rotations here never refresh the deposit seed (crypto §3 allows it: then a
\* node that has not read the rotation's keys.0 is refused, AMBIGUITIES.md
\* residue 2).
Notice(x) ==
  /\ online[x] /\ x \in Holding /\ x \notin stranded /\ x \notin dep[x]
  /\ \/ CanOpen(x) /\ Top.ep \notin sec[x] /\ ~\E k \in storeRot : FromStore(x, k)
     \/ ~CanOpen(x)
  /\ Enc(x) \cap Est(x) # {}
  /\ stranded' = stranded \cup {x}
  /\ leakP' = (leakP \/ NewestOf(Enc(x) \cap Est(x)) \notin sec[x])
  /\ UNCHANGED <<ep, made, kn, sec, fsec, dep, hld, removed, granted, storeRot, before, bx, rd,
                 steps, sealed, sealedRot, via, enc, online, budget>>

GoOff(x) == /\ online[x] /\ budget.off < Offs
            /\ online' = [online EXCEPT ![x] = FALSE] /\ budget' = [budget EXCEPT !.off = @ + 1]
            /\ UNCHANGED <<ep, made, kn, sec, fsec, dep, hld, removed, granted, storeRot, before,
                           bx, rd, steps, sealed, sealedRot, via, stranded, enc, leakP>>
GoOn(x) == /\ ~online[x] /\ online' = [online EXCEPT ![x] = TRUE]
           /\ UNCHANGED <<ep, made, kn, sec, fsec, dep, hld, removed, granted, storeRot, before,
                          bx, rd, steps, sealed, sealedRot, via, stranded, enc, leakP, budget>>

Next ==
  \/ \E a \in Admins : Rotate(a) \/ Register(a) \/ WriteContent(a)
                       \/ (\E k \in Ids : LogRot(a, k))
                       \/ (\E m \in Nodes : Reseal(a, m) \/ Grant(a, m))
  \/ \E m \in Departing : Remove(m)
  \/ \E x \in Nodes : \/ Notice(x) \/ GoOff(x) \/ GoOn(x)
                      \/ (\E k \in Ids : Recv(x, k) \/ TakeSealed(x, k) \/ TakeSealedRot(x, k)
                                         \/ Plant(x, k))
                      \/ (\E b \in bx : RecvBox(x, b))

\* Weak fairness of honest steps; eager rotation, removal, grants, writes,
\* going offline and planting are unfair.
Fairness ==
  /\ \A a \in Admins : /\ WF_vars(RotateForced(a)) /\ WF_vars(Register(a))
                       /\ \A k \in Ids : WF_vars(LogRot(a, k))
                       /\ \A m \in Nodes : WF_vars(Reseal(a, m))
  /\ \A x \in Nodes : /\ WF_vars(Notice(x)) /\ WF_vars(GoOn(x))
                      /\ \A k \in Ids : /\ WF_vars(Recv(x, k)) /\ WF_vars(TakeSealed(x, k))
                                       /\ WF_vars(TakeSealedRot(x, k))
                      /\ WF_vars(\E b \in bx : RecvBox(x, b))

Spec == Init /\ [][Next]_vars /\ Fairness

-----------------------------------------------------------------------------
GCur == {e \in made : ~\E f \in made : e \in ep[f].sup}

TypeOK == /\ made \subseteq Ids /\ removed \subseteq Departing /\ granted \subseteq Late
          /\ Withhold \subseteq Admins
          /\ \A x \in Nodes : sec[x] \subseteq made /\ kn[x] \subseteq made
                              /\ fsec[x] \subseteq made /\ via[x] \subseteq Nodes
                              /\ rd[x] \subseteq bx

\* crypto §4 covers rule, its purpose: content a writer encrypted while it
\* knew of M's departure is never readable by M.
NoLeak == \A c \in enc : \A m \in c[2] : c[1] \notin sec[m]
\* permissions §3 "requires rotating every role secret M could open": a
\* departed holder never holds an epoch whose rotation did not box it.
DepartedLocked == \A m \in removed : \A e \in sec[m] : m \in ep[e].ob
\* crypto §4: a secret from a planted box (a non-holder's pending or invalid
\* commit) never becomes an encrypting key: nothing was wrapped, boxed,
\* history-boxed or signed under it.
NoPlantedKey == ~leakP

\* permissions §3 / sync §5: every current holder eventually opens every
\* current epoch (by claims, downloads or re-seal) ...
CurrentOpens == <>[](\A x \in Holding \ removed : GCur \subseteq sec[x])
\* ... and reads the sync ID: every epoch content was written under (for a
\* grantee, older epochs by the history box, crypto §4).
ReadsAll == <>[](\A x \in Holding \ removed : \A c \in enc : c[1] \in sec[x])
=============================================================================
