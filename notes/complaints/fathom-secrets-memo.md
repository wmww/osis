# fathom-secrets-memo
> Summary: footguns met while finding the secrets memo's stale answer.

- The issue (and brief) pointed at the amend path; the cause was the stamp table's removal rule (`memo::Table::wrote`), invisible from the engine. What found it: printing each `secrets: decode` keep/held with its deps' `seen` and current stamps (`seen 0`, then the removal put the stamp back to 0). Worth a debug helper on `Memo` that dumps an entry's deps for one key.
- Two nodes' memos interleave in one test's stderr; tag every trace line with the memo's address or node, else a held answer looks like it came from nowhere.
