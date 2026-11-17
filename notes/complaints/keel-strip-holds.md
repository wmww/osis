# keel-strip-holds
- The commits the brief suspected for the failing strip test (5a3797094, efcd394ab, 06e39ab05) all pass it; bisecting with `tools/bin-at` found 45975c07b (rotation own covers). Each bin-at build of osis-sync took 3-6 minutes; five in a row was most of an hour.
- Scale tests comparing n with 10n break silently when the two sizes sit on either side of a mechanism threshold (paging): a count that is 0 at n fails `linear`/`flat` at 10n. Lowering the page threshold moved four engine and two osis scale tests across it.
- Per-make instruction counts over 20 makes swing by 10-20% with where compactions fall; 100-make windows are steadier.
