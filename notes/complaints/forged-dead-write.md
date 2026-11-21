# forged-dead-write
> Summary: footguns met fixing the forged embedded-char death (a dead write no held body supersedes).

- The issue's leads named the right class (a creation `held_writes` leaves out) but not where: an `OSIS_PROBE_` dump of the dead write, the part, the state and the held writes at the `Corrupt` site found it in one replay. A `Corrupt` with no context costs a probe build each time; the error could carry the `Won`.
- A foreground `cargo test -p osis-engine --lib` after editing crdt rebuilt past 120 s and moved to the background mid-call: start engine runs after a crdt edit in the background.
- Extending the hostile generator with the class's inputs (forged embedding copies, register copies) found a join convergence bug in the first Small run that the class's hand tests never reached (a position write at a register write's stamp lost from top-2 when a cut copy's creation goes): the generator lagged the forged-input classes the issues named. Run the generator over a new input class before trusting the area.
- `git commit` in an `&&` chain with nothing staged stops the chain silently; a probe ran nothing once.
