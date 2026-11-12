# order-covered-held
> Summary: footguns met while fixing the per-part keep bound (order seed 723062969594).

- The order harness's held-model dump names aspects by model number (`name: 105`) while the failure line names the AK (`t:reg.0`): matching them took decoding the whole input by hand. Printing the AK beside each model aspect would save that.
- No shrink was needed: reading the dumped model input (settings, which parts share a commit) found the cause directly. Read the dump before reaching for a step-dropper.
- A blanket `sed s/body_keeps/part_keeps/` also renamed an unrelated held-model test (`an_original_without_its_body_keeps_its_versions`): grep word-boundary hits before a rename sed.
