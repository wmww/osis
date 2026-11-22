# open10's junk property fails on random worlds
> Summary: held-model `spec_story::evidence_along_joined_chained_paths_large` fails on main from OSIS_HELD_START=72021111173: 2 random worlds (first seed 72021111223) report P10-junk at step 15 (an honest node logs an unchained edge-class commit on a thing outside its unit). A model or property bug, not yet read.
> Priority: normal
> Tags: tests, held-model

## What
`OSIS_HELD_START=72021111173 cargo test -p held-model --test it -- --ignored --exact spec_story::evidence_along_joined_chained_paths_large`: `2 worlds fail, first: random seed 72021111223: Fail { prop: "P10-junk", step: 15, sid: 13, id: 8, reader: None, full: None }`. Seen at a gate of a branch touching only crdt-model's hostile generator and reader (unused here); main's binary fails alike.

## To read
Whether the world is a real leak (an honest node logging junk under S) or the check's `chained` over the full held set is stale: `Evidence::chained` per held set is memoized on the world and cleared by a write (64f6017ed), so a memo kept past a change would give this. Shrink seed 72021111223 to a hand-written world.
