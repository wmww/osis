# lowered-growth
- The growth test's census names row kinds only; finding which `c/` row was extra took a throwaway probe (scan `c/` keys at n and 10n, diff, decode the meta). A test helper listing held commits with kind and author would have saved several build rounds.
- The extra commit was a repair snapshot, not anything the two branches touched: they only shifted which of two suspect lists arrived first (one went out on a connection replaced at first contact). Races like this show up as "fails only with both branches".
