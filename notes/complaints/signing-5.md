# signing-5 (review)
> Summary: footguns met reviewing account-signing step 5.

- `roles-model -- N epochs|epochs-exh` exits 0 with hard failures; only the printed stats (and a "first failing world" after all families) tell. A wrapper piping through `tail` sees nothing wrong.
- A probe `eprintln!` in a passing test is captured: counting its lines needs `--nocapture`, or the count reads 0 and suggests the case is never reached.
