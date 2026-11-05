------------------------------- MODULE Depth0MC -------------------------------
(* Instance constants for Depth0.tla (a .cfg cannot write tuples).           *)
EXTENDS Depth0

\* holder actor M of A; m1 removes device D (an admin of M) from M; m2 may
\* fork M and a1 (the one admin of A) may rotate A once unprompted
mActs == <<"A", "M">>
mMem == {<<"A", "a1">>, <<"A", "M">>, <<"M", "m1">>, <<"M", "m2">>, <<"M", "D">>}
mAdm == {<<"A", "a1">>, <<"M", "m1">>, <<"M", "m2">>, <<"M", "D">>}
mLearners == {"a1", "m1", "m2"}
mDeps == {<<"D", "M", "m1">>}
mEager == {<<"m2", "M">>, <<"a1", "A">>}
mG == << <<"A", "M">> >>

\* 2-cycle X <-> Y (each a holder of the other); x1 removes D from X
cActs == <<"X", "Y">>
cMem == {<<"X", "x1">>, <<"X", "D">>, <<"X", "Y">>, <<"Y", "y1">>, <<"Y", "X">>}
cAdm == {<<"X", "x1">>, <<"Y", "y1">>}
cLearners == {"x1", "y1"}
cDeps == {<<"D", "X", "x1">>}
cEager == {<<"y1", "Y">>}
\* ... and E leaves Y at the same time
c2Mem == cMem \cup {<<"Y", "E">>}
c2Deps == cDeps \cup {<<"E", "Y", "y1">>}

\* ... and Y has a second admin y2
cyMem == cMem \cup {<<"Y", "y2">>}
cyAdm == cAdm \cup {<<"Y", "y2">>}
cyLearners == cLearners \cup {"y2"}
cyEager == {<<"y2", "Y">>}

\* 3-cycle: X holds Z's role, Z holds Y's, Y holds X's (X in Y, Y in Z, Z in X)
tActs == <<"X", "Y", "Z">>
tMem == {<<"X", "x1">>, <<"X", "D">>, <<"X", "Z">>,
         <<"Y", "y1">>, <<"Y", "X">>, <<"Z", "z1">>, <<"Z", "Y">>}
tAdm == {<<"X", "x1">>, <<"Y", "y1">>, <<"Z", "z1">>}
tLearners == {"x1", "y1", "z1"}
tDeps == {<<"D", "X", "x1">>}

\* W holds X, X <-> Y; w1 removes D from W (a departure below a cycle)
wActs == <<"W", "X", "Y">>
wMem == {<<"W", "w1">>, <<"W", "D">>, <<"X", "x1">>, <<"X", "W">>, <<"X", "Y">>,
         <<"Y", "y1">>, <<"Y", "X">>}
wAdm == {<<"W", "w1">>, <<"X", "x1">>, <<"Y", "y1">>}
wLearners == {"w1", "x1", "y1"}
wDeps == {<<"D", "W", "w1">>}
wEager == {<<"y1", "Y">>}

\* rule 4: grants in the agreed order (none: Fresh)
noGrants == << >>
\* X holds Y first, so Y holding X gives no key access; and the reverse
gYX == << <<"Y", "X">>, <<"X", "Y">> >>
gXY == << <<"X", "Y">>, <<"Y", "X">> >>
\* under gXY, y1 (y2) does not hold the earlier grant at first: it seals Y to X
hideY1 == {<<"y1", <<"X", "Y">> >>}
hideY2 == {<<"y2", <<"X", "Y">> >>}
\* 3-cycle: X holds Y, Y holds Z first; Z holding X gives no key access;
\* x1 lacks the grant of X holding Y at first: it seals X to Z
tG == << <<"Y", "X">>, <<"Z", "Y">>, <<"X", "Z">> >>
tHide == {<<"x1", <<"Y", "X">> >>}
\* below: W holds X, X holds Y first; Y holding X gives no key access
wG == << <<"X", "W">>, <<"Y", "X">>, <<"X", "Y">> >>
\* removed-member writer: G <- X1 <- X2 <- {W, R}; b, the one admin of X1 and
\* X2, does not sync G; W writes G through X1 and X2; b removes W from X2;
\* a1 (G's admin) syncs only G (it sees X1's keys.0, never X2's commits)
rActs == <<"G", "X1", "X2">>
rMem == {<<"G", "a1">>, <<"G", "X1">>, <<"X1", "b">>, <<"X1", "X2">>,
         <<"X2", "b">>, <<"X2", "W">>, <<"X2", "R">>}
rAdm == {<<"G", "a1">>, <<"X1", "b">>, <<"X2", "b">>}
rLearners == {"a1", "b", "W", "R"}
rDeps == {<<"W", "X2", "b">>}
rVia == {<<"W", "G">>}
rNoSync == {<<"a1", "X1">>, <<"a1", "X2">>, <<"b", "G">>}
rG == << <<"G", "X1">>, <<"X1", "X2">> >>
\* ... with no other member of X2 syncing G (R absent)
r0Mem == rMem \ {<<"X2", "R">>}
r0Learners == rLearners \ {"R"}
\* ... W may rotate G once unprompted (sealing X1 at a keyset it opens)
rEagerW == {<<"W", "G">>}
\* the dropped Box rule (D0_box_rule, D0_box_ok): 3-cycle,
\* B in A, C in B, A in C; p the admin of A and B (so p holds a role on C
\* through A), q of C; p removes D from A. In order B in A, A in C, then C in
\* B closes the cycle: no key access. p lacks A in C at first, so it seals B to
\* C (a blind box) at C's keyset before it holds C's secret
bActs == <<"A", "B", "C">>
bMem == {<<"A", "p">>, <<"A", "D">>, <<"A", "B">>, <<"B", "p">>, <<"B", "C">>,
         <<"C", "q">>, <<"C", "A">>}
bAdm == {<<"A", "p">>, <<"B", "p">>, <<"C", "q">>}
bLearners == {"p", "q"}
bDeps == {<<"D", "A", "p">>}
bG == << <<"A", "B">>, <<"C", "A">>, <<"B", "C">> >>
bHide == {<<"p", <<"C", "A">> >>}
\* forked holder anchors (cycle harness seed
\* 1838): m1 and m2 admin both A and M; m1 removes D from M; each may rotate M
\* once more unprompted, so two keysets of M knowing the removal can stand
\* side by side; each then rotates A (its box to M's first keyset is stale)
\* sealing M at the keyset it holds, so A's two current epochs anchor M at both
fActs == <<"A", "M">>
fMem == {<<"A", "m1">>, <<"A", "m2">>, <<"A", "M">>, <<"M", "m1">>, <<"M", "m2">>, <<"M", "D">>}
fAdm == {<<"A", "m1">>, <<"A", "m2">>, <<"M", "m1">>, <<"M", "m2">>}
fLearners == {"m1", "m2"}
fDeps == {<<"D", "M", "m1">>}
fEager == {<<"m1", "M">>, <<"m2", "M">>}
fG == << <<"A", "M">> >>
\* ... and device E reads A; m1 removes E from A (Alone: while the anchors
\* fork the removal goes without A's rotation)
eMem == fMem \cup {<<"A", "E">>}
eDeps == {<<"E", "A", "m1">>}
\* above A: A holds G's role; a1 (admin of A and G) removes device E from A,
\* the removal alone (Alone "any"); a2 (A's other admin) may fork A once
\* unprompted, a1 may rotate G once unprompted
uActs == <<"G", "A">>
uMem == {<<"G", "a1">>, <<"G", "A">>, <<"A", "a1">>, <<"A", "a2">>, <<"A", "E">>}
uAdm == {<<"G", "a1">>, <<"A", "a1">>, <<"A", "a2">>}
uLearners == {"a1", "a2"}
uDeps == {<<"E", "A", "a1">>}
uEager == {<<"a2", "A">>, <<"a1", "G">>}
\* ... with a1 the one admin of A (two admins both rotating A for the removal
\* fork it, and the merge and G's moves after it outrun MaxE 7) and r, a
\* device reading G only through A
u1Mem == (uMem \ {<<"A", "a2">>}) \cup {<<"A", "r">>}
u1Adm == uAdm \ {<<"A", "a2">>}
u1Learners == {"a1", "r"}
u1Eager == {<<"a1", "G">>}
uG == << <<"G", "A">> >>
\* ... and g2, a second admin of G not reading A (it re-seals A where a1's
\* rotation of G left it out)
u2Mem == uMem \cup {<<"G", "g2">>}
u2Adm == uAdm \cup {<<"G", "g2">>}
u2Learners == uLearners \cup {"g2"}
u2NoSync == {<<"g2", "A">>}
\* ... with no rotation of A made without knowing the removal (a2 may not
\* rotate unprompted)
u2Eager == {<<"a1", "G">>}
\* readers above (issues/blocked-walk-stops-at-readers.md): M holds A's role,
\* A holds G's; R, the one admin of G, reads M (so A through M) and may
\* rotate neither; a1 the admin of A, m1 of M; m1 removes E from M
vActs == <<"G", "A", "M">>
vMem == {<<"G", "R">>, <<"G", "A">>, <<"A", "a1">>, <<"A", "M">>,
         <<"M", "m1">>, <<"M", "R">>, <<"M", "E">>}
vAdm == {<<"G", "R">>, <<"A", "a1">>, <<"M", "m1">>}
vLearners == {"R", "a1", "m1"}
vDeps == {<<"E", "M", "m1">>}
vG == << <<"G", "A">>, <<"A", "M">> >>
\* ... and g2, a second admin of G reading neither A nor M (it re-seals A
\* where R left it out)
v2Mem == vMem \cup {<<"G", "g2">>}
v2Adm == vAdm \cup {<<"G", "g2">>}
v2Learners == vLearners \cup {"g2"}
v2NoSync == {<<"g2", "A">>, <<"g2", "M">>}
\* first admin (issues/owner-to-first-admin.md, Risks 1): F (device f1) is
\* T's first admin, its record edge first in grant order; T is granted on F
\* later, closing a cycle, so keyless; t1 (T's other admin) removes F from T,
\* after which T's grant on F has key access and F's epochs need a re-seal to
\* T. f1 writes T through F until it knows the removal; f1 may rotate F once
\* unprompted
faActs == <<"F", "T">>
faMem == {<<"F", "f1">>, <<"F", "T">>, <<"T", "F">>, <<"T", "t1">>}
faAdm == {<<"F", "f1">>, <<"T", "t1">>}
faLearners == {"f1", "t1"}
faDeps == {<<"F", "T", "t1">>}
faEager == {<<"f1", "F">>}
faVia == {<<"f1", "T">>}
faFirst == {<<"T", "F">>}
faG == << <<"T", "F">>, <<"F", "T">> >>
\* ... and T was plain (derived from F) until t1's grant gave it its own
\* secrets (T's initial epoch); f1 lacks that rotation at first
faPlain == {<<"T", "F">>}
faUnaware == {<<"f1", "T">>}
\* derivation alone: no grant of T on F
fdMem == faMem \ {<<"F", "T">>}
fdG == << <<"T", "F">> >>
=============================================================================
