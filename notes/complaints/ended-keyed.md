# ended-keyed
- TLC runs under `tools/heavy` waited a long time for the lock behind other gates; a parse error only shows after the wait. Parse first without the lock: `java -cp ~/.cache/tla/tla2tools.jar tla2sany.SANY Depth0MC.tla`.
- Depth0MC.tla shares one namespace across every instance: short prefixes (`e`, `r`) collide with existing ones.
- `run.sh depth0` now takes about 420 s at 4 workers under `tools/heavy`, near its 598 s wall limit (D0_nc3 and D0_gone_live dominate).
