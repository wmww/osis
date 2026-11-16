# keel-diff-model
- Seed 6's item 2 hid two more bugs behind it (the kept-unread judgement ignoring sync secrets held from own reading; the body clause reading plaintext only): fixing one disagreement exposed the next each time, so budget for a chain.
- The full-size differential had never been run green: about a third of its seeds fail on main too, so "run it at OSIS_FULL" needs a baseline run of the same seeds to tell new failures from old (two heavy holds, each about 700 s wall, over the `heavy` wall limit by a hung seed's 600 CPU-s tail).
