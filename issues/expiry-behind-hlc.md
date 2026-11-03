# A short expiry fails the write when the HLC is ahead of the clock
> Summary: since ephemeral writes became commits (eph-unify B2), an expiry only seconds ahead of `Engine::now` fails `commit` with "expires not after the commit's ts" once the node has read a commit from a clock further ahead.
> Tags: engine, ephemeral

Found by sim-sweep, `ephemeral` seed 761500013 with the expiry taken from `now` (node 1, a typing flag 5 to 30 s ahead; skews reach 20 s each way). An app sets such an expiry from its own clock, so a typing flag or cursor fails on a node whose peers' clocks run ahead, with no way to know except reading the HLC. Decide: raise the expiry to just past the commit's `ts`, or give the API an expiry relative to the commit. The sim's `random_ephemeral` takes it from the HLC meanwhile.
