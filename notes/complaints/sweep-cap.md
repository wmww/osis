# sweep-cap
- An engine-level test at `MAX_DELTA_BARE` (2^18 hidden text chars) takes about 35 s in dev, so it is by hand; the cap is a const with no test knob, so the default test is the crdt-level one.
