# a1-spec-review
> Summary: Mishaps reviewing the A1 spec draft.

- `tools/spec_map.py --gaps` checks only spec/, so a draft's broken anchors are found by hand: a scratch script matching each cited anchor piece against the draft's section text did it in seconds; worth a `--against <dir>` flag for any spec rewrite drafted in notes/.
- The tool checks only an anchor's name (before `:`), so a gloss the new text makes false (`self-removal: authority through the holder does not count`) passes silently.
- A model claim ("dispute candidates include self-removals") was only judgeable by a probe test; a throwaway test appended to tests.rs and reverted with `git checkout` was the quickest way.
