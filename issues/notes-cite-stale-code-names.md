# Notes and issues cite code names that no longer exist
> Summary: Backticked function and test names in notes/ and issues/ rot when code is renamed or deleted (about 60 such names on main); nothing checks them. Proposed: `tools/code_refs.py`, run by policy.py, failing on a backticked snake_case name absent from every tracked source file, with an allow list for third-party names and placeholders.
> Priority: low
> Tags: tools

A probe over main (backticked lowercase identifiers containing `_`, split on `::` and punctuation, against every word of tracked `.rs .tla .py .sh .toml .cfg .txt .osis .json` files; 2 s) found 87 names in notes/ and issues/ that no source contains. About 60 are stale code names: test names in issues/gate-five-minutes.md, issues/tests-4x.md and issues/test-consolidation.md (`rotation_holds_large`, `paged_apply_matches_whole_large`, `member_churn` 18 times), fns in notes (`authors_on`, `account_counts`, `match_secret`, `load_schema`, `freed_delete_secrets`). The rest are third-party or OS names (`posix_fadvise`, `set_surrounding_text`, `perf_event_paranoid`, `ptrace_scope`, `serde_core`) and placeholders (`do_x`). spec/ was left out: its names are wire and grammar terms (`case_id`, `secret_r`).

## Steps
1. `tools/code_refs.py`: the probe above as a check (the scan of tracked files as `tools/doc_refs.py` does), over notes/ and issues/ minus notes/complaints/ and the Investigations section of notes/time-limits.md (a record of what ran then); exit 1 listing `file: name` per hit.
2. `tools/code_refs_allow.txt`: one name per line with a reason (`third-party`, `placeholder`); union-merged (.gitattributes) with a stale-line check in `UNION_STALE` (a listed name now found in the code, or cited nowhere, fails).
3. policy.py runs it beside doc_refs; `tools/policy_test.py` plants one stale name; notes/gate.md, Policy checks, gains a sentence.
4. The first run's ~60 stale names are fixed in the same branch (a prose job: name the current function, or drop the sentence if what it described is gone).
