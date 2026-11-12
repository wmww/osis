# order-covered-held
> Summary: footguns met while fixing the per-part keep bound (order seed 723062969594).

- The order harness's held-model dump names aspects by model number (`name: 105`) while the failure line names the AK (`t:reg.0`): matching them took decoding the whole input by hand. Printing the AK beside each model aspect would save that.
- No shrink was needed: reading the dumped model input (settings, which parts share a commit) found the cause directly. Read the dump before reaching for a step-dropper.
- A blanket `sed s/body_keeps/part_keeps/` also renamed an unrelated held-model test (`an_original_without_its_body_keeps_its_versions`): grep word-boundary hits before a rename sed.
- tools/gate_failures.py matches only an order failure's seed line, which carried the emphasis and steps but not the failure text, so a known_failures pattern could only name the emphasis (the line this branch removed matched any Settings failure). The seed line now ends in the failure's first line.
- The 300-seed plain sweep took 1058 s, 1.8x the `heavy` wall limit (logged in notes/time-limits.md).
