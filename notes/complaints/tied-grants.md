# tied-grants
- `cargo test -p osis --test it tied:: tags::` fails ("unexpected argument"): several filters go after `--`.
- A test probe that added `w.advance(120_000)` while a self-removal could not be placed ran for minutes (killed at 200 s, no output); after the placement fix the same advance took 28 ms. A storm in `World::advance` gives no sign: a per-advance step cap with a panic would point at it.
- Adding `tied` to every `since: None }` edge literal by sed (~60 sites) worked; `ct::Edge` has no `Default`, so every new field touches every test literal.
- Review: the sim World could cut a database off the network only as a whole; a partition from one server (the case the obligation's wait must survive) needed `World::set_reachable`.
- I reverted my own uncommitted edits with `git checkout <file>` after a fix-disabled probe; for such probes, edit back by hand or commit a wip first.
