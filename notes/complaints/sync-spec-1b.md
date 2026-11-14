# sync-spec-1b complaints
> Summary: Workflow snags met while resolving the sync spec's TODO(area) markers and fixing the split's pointer sweep.

- The spec split repointed citations by old section number alone, so one old section (§10) became one new section for ~330 citations whose rules went to five files. A split that moves rules should repoint by rule (anchor or keyword), or leave the old pointers failing a check, not silently wrong.
- TODO markers cited inputs-note line numbers ("lines 57-63", "162-171") that had already drifted when read; cite the input's source tag or a quoted phrase instead.
