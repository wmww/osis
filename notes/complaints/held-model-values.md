# held-model-values
- The suggested sabotage (a held text delete beating a later undelete, `seq.rs` `join_flag`) and two removal sabotages (a set element's frag kept under its own reset; a list element shown above its reset) all pass quick: quick's random histories draw no list delete and no effective set removal. A hand history shows held-model catches the set one at once. The quick sabotage that fails is a list read path (elements reversed).
- held-model's `settle` never fetched back a body dropped as invalid that turned valid again; the new generator's histories reached it at seed 184 of 800 (props at 2400 seeds), not at tier 1.
- Wrapped one cargo run in `timeout` by reflex; it printed nothing and wasted a round.
