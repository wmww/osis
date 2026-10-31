# fair-input
- Driver tests on `InProcess` cannot measure a wait from outside: every probe also pays its own round trip (about a dozen task hops on a current-thread runtime, one flood read served per hop). The flood test bounds the round trip instead and leaves source fairness to a unit test of `Turns`.
