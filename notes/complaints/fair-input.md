# fair-input
- Driver tests on `InProcess` cannot measure a wait from outside: every probe also pays its own round trip (about a dozen task hops on a current-thread runtime, one flood read served per hop). The flood test bounds the round trip instead and leaves source fairness to a unit test of `Turns`.
- Review: wall-time old/new comparisons of a sub-second loopback sync at load 17-22 swung 3x run to run (medians crossed between batches); `/usr/bin/time` CPU seconds over 10 runs each were steady enough to compare.
