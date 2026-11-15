# undo-create-home
- Unwinding a feature spread over ~25 commits: reverse-applying their test hunks with `git apply -R -3` in order left half-applied files without markers once one patch conflicted (later patches then skip "not in index" files). Hand edits guided by compile errors and test failures were faster.
- A scripted `str.replace` of an indented line also matched inside a deeper-indented copy, shifting the next line's indent: anchor such replacements on whole lines.
- The create-home default had masked that a granted or linked thing in no synced group is never served by its granter (issues/shared-thing-in-no-synced-group.md): three sync tests failed only after the default went.
