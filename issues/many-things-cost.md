# What a node holding many things still pays per write
> Summary: Making one plain thing under the account root still grows with what is held (debug instructions: 32 M at 100 held, 44 M at 200, 48 M at 400): the account root's `holds.0` state written whole below a page, debug-only whole checks, and small remainders in read and drop settles. A 2000-thing commit costs about 17 M instructions per thing (debug).
> Priority: normal
> Tags: engine, sync, performance

Measured with `tools/icount` (per make: the run with 20 more makes less the run without) and `tools/cpuprof` on osis `it` (debug), profile shares scaled by the instruction count. What one thing stores, downloads and signs, and the changes left for it: notes/thing-cost.md.

- **Whole state below a page.** The account root's `holds.0` gains a strong per make, and a state at or below `PAGE_TARGET` (64 KiB) is encoded and written whole at each write (`pages::write_full` from `Tx::write_state`, also in `shred_covered`): about 3.5 M of the 16 M growth from 100 to 400. Bounded by the page target, but a make then costs O(min(aspect, 64 KiB)): an aspect that grows by one element per write should write what it gained (a delta or a page of the tail), not the whole.
- **Debug-only whole checks** grow with every held commit per transaction: `validity::misjudged` after each re-judge (about 4 M of the growth), `Timeline::check_first_held` (about 1.7 M). Release builds skip them; tests pay them, so a test's runtime grows with n squared.
- **Small remainders**, about 1 M each from 100 to 400, unexplained: sync `Read::settle` (`drop_body` via `retention::drop_part_for`), `Engine::follow`, `Status::held_elsewhere`.
- **Per thing of a big commit** (`commits::changes_on_as_many_things_spec_requirements_decentralization`, 38 G at 2000 things): `write::framing_for` and `follow_certificates` (a `Piece::Chain` per thing, each naming the account's commits). A commit's delete keys are found once per delete base (`secrets::KeyCache`, `published_keys`).
