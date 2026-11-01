# sweep-9-host-store
- Comparing main vs branch needed the bench written twice (main's `HostStore::open` took a `Backend`): `tools/bin-at --patch` with a hand-made diff of main's file.rs worked, but the patch had to be built outside git (`diff -u` of two scratch copies).
- The 2^20 reconcile bench takes about 6.5 min, nearly all of it the fill; the budget numbers at 10^5 come in 25 s.
