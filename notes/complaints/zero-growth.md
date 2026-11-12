# zero-growth
- The growth census (`local_census`) groups rows by key prefix only: finding which commits stay needed a throwaway per-commit dump (kind, drop reason, cover author). A doc-hidden helper for it would have saved a round.
- roles-model `forget` (the exhaustive family, 8 policies) holds the heavy lock about 11 min; a single-threaded search over the whole member family is far slower, so `forget-any` samples one world in 200.
