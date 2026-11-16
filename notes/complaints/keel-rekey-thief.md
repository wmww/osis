# keel-rekey-thief
- `tools/heavy script.sh` fails with "Exec format error" without a shebang line.
- `Meta::missing_parts` counts parts whose body is absent, not parts the node cannot decrypt: a removed node shows `Body` for a write it cannot open. Test readability by value (`engine.get`).
- The model searches pick X's moves from judged state, so any policy change reshuffles the random worlds: a pre-existing rare failure can surface as if new (issues/retake-on-thief-merge.md).
