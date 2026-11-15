# test-cost
- A whole-binary plus per-module icount of three `it` binaries in one `tools/heavy` hold ran 469 s against the 439 s heavy wall limit; split such a measurement into two holds.
- Env vars named `OSIS_*` that testenv does not know fail every test at once (0.00 s): a temporary probe variable needs another prefix.
- `tools/pertest.py run` builds the checkout as it is: to profile a copied binary, write `OUT.todo` and call `pertest.py measure` under `tools/heavy`.
