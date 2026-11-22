# stranded-rotation
- A one-seed property replay that fails early takes 3 s; the same replay passing took 48 s, since a passing seed plays its whole history: a fix's replay costs far more than the failure's.
- The rotation tests_members worlds cost about 2-3 s each to build in a cold process; three tests on one cached world still pay it once per test binary run, so new holder-actor tests sit at the "few seconds" edge.
