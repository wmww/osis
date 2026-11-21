# cbor-once
- Making `Decoder::item` generic (two instantiations) moved the decoder's tiny helpers (`byte`, `len`, `spend`, `enter`, `in_order`, `short`, `remaining`) out of line at opt-level 1: +14% instructions on `decode_peak_within_the_bound` until they were marked `#[inline]`. `nm -S --demangle <test binary> | rg 'Decoder>::'` shows which helpers stand alone; there is no perf or valgrind on the box to find hot spots otherwise.
- `gen` is a reserved keyword in edition 2024: a test helper named `gen` fails to parse.
- `git rm` then a Python edit chained with `&&` stopped at `git rm`'s refusal (the file had changes since its last commit): the edit silently never ran (notes/build.md Footguns already warns of `&&` chains).
