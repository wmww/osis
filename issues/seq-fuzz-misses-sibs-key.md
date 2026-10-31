# Seq fuzz does not catch a Sibs::key ignoring sits
> Summary: `fuzz_seq` (4800 scripts, merged joins included) passes with a `Sibs::key` that ignores `sits`; only two unit tests catch it. Undo lower-key and forged-copy shapes are too rare in random scripts. Low.
> Tags: tests, crdt

Fix direction: bias the generator toward undo of moves and forged copies (a weight, or a dedicated script family), then check the mutant (key ignoring `sits`) fails within the default script count.
