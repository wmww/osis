# retain-rule
> Summary: workflow notes from the ended-keyless retain way fix.

- `tools/mutate.py` refuses two plants on one OLD site (`overlap`) only after argument parsing, with exit 0 from the wrapper's echo: easy to miss in a background run. Plant the second at a different site (the callee's body).
