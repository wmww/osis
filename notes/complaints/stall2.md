# stall2
- `cargo test -p osis-node --test it stream::a stream::b` fails: several name filters need `--` before them (`-- stream::a stream::b`).
- Unit-testing the `MAX_AHEAD` bound needs about 70 MiB of frames per test (no smaller seam: the bound is the spec's); a served session also closes on more than `MAX_UNANSWERED` bytes in one input, so filler goes one frame per input.
