# lockout-two
- Tier 1 under TLC load: `runtime::single_use_direct_keeps_key_in_process_spec_permissions_7` failed once ("admin delete key not supplied"), passed alone. Possibly load-flaky.
- Lockout.tla two-rogue instances explode with any h rotation or write (5 nodes x any-order delivery): MaxDue 1 + 1 write passed 45M+ states without finishing; kept L_two at no writes (9M states) and L_two_write (35M, 45 min at 4 workers under load).
- run.sh gives no progress while an instance runs (TLC log in a temp dir until the end); a long `all` instance looks hung.
- Review: two-rogue Lockout with one honest rotation (MaxH 1, MaxDue 1, no writes) passed 21M distinct states with the queue still growing after 6 min (8 workers); stopped. TLC `-simulate` was the affordable check.
- The flaky runtime test reproduces only with the whole `runtime::` module run 4x at once (issues/osis-runtime-tests-flaky.md); the test alone 120x passed.
