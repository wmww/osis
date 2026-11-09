---- MODULE MCStream ----
EXTENDS NetStream
Es3 == {"e1","e2","e3"}
Es2 == {"e1","e2"}
Ls1 == {"L1"}
Ls2 == {"L1","L2"}
EL1 == [e \in Es3 |-> "L1"]
EL2 == ("e1" :> "L1") @@ ("e2" :> "L1") @@ ("e3" :> "L2")
EL3 == ("e1" :> "L1") @@ ("e2" :> "L2") @@ ("e3" :> "L2")
Au == ("e1" :> "a") @@ ("e2" :> "b") @@ ("e3" :> "b")
Au3 == ("e1" :> "b") @@ ("e2" :> "b") @@ ("e3" :> "a")
DialsOne == {<<"a","b">>,<<"a","c">>}
DialsOther == {<<"b","a">>,<<"c","a">>}
DialsBoth == DialsOne \cup DialsOther
STORES3 == {"a","b","c"}
STORES2 == {"a","b"}
====
