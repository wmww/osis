------------------------------- MODULE Depth0MC -------------------------------
(* Instance constants for Depth0.tla (a .cfg cannot write tuples).           *)
EXTENDS Depth0

\* holder actor M of A; m1 removes device D (an admin of M) from M
mActs == <<"A", "M">>
mMem == {<<"A", "a1">>, <<"A", "a2">>, <<"A", "M">>,
         <<"M", "m1">>, <<"M", "m2">>, <<"M", "D">>}
mAdm == {<<"A", "a1">>, <<"A", "a2">>, <<"M", "m1">>, <<"M", "m2">>, <<"M", "D">>}
mLearners == {"a1", "a2", "m1", "m2"}
mDeps == {<<"D", "M", "m1">>}
mFork == {<<"m2", "M">>}

\* the same with one admin of A, a1, that may also rotate A once unprompted
m1Mem == mMem \ {<<"A", "a2">>}
m1Adm == mAdm \ {<<"A", "a2">>}
m1Learners == {"a1", "m1", "m2"}
m1Eager == mFork \cup {<<"a1", "A">>}

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

\* rule 4 (CycleCheck "nocycle"): grants in the agreed order
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
tEager == {<<"y1", "Y">>, <<"z1", "Z">>}
\* below: W holds X, X holds Y first; Y holding X gives no key access
wG == << <<"X", "W">>, <<"Y", "X">>, <<"X", "Y">> >>
=============================================================================
