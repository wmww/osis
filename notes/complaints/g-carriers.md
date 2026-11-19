# g-carriers
- `local_census` families keep the trailing `/` ("pc/", not "pc"): a lookup by the bare prefix reads 0 rows and an "is zero" assert passes vacuously. Probe every row-count assert with the mechanism off.
- `fires_owed().last()` is the highest FireId, not the newest fire: in a world with any other owed fire (a grant's sealed ticket) it picks that one. tests/it/carriers.rs diffs the owed set instead; strangers.rs still uses `.last()` (fine there: no other owed fire).
