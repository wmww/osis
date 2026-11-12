# revocation-carol complaints
- The sim's gap line `only 2: ["C at [] pending there None"]` reads as "pending at node 2"; it means node 2 holds C and node 0 does not (and does not hold it pending). Led to a wrong brief ("3 commits pending at node 2").
- A seed failure's gate unit is only the `seed N, EMPHASIS (replay: ...)` line; the cause (`held-model differs: ...`) is on the next line, so an order known-failures pattern can only be as narrow as the emphasis.
- `OSIS_ORDER_SHRINK=1` ran 9 min and took a 72-commit history to 70.
