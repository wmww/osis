# prose-issues-2
- issues/ is ~500 KB over 187 files; one agent cannot read it all in context, so the pass ran as four forks by byte size. Cross-batch dedupe then works only from summary lines.
- Several issues (net-reconnect, net-shared-set, thing-lifetimes before this pass) are design documents for built code with 50-100 code comments citing them; moving them to notes means mass comment edits.
- `claudewait` does not know Agent task IDs; only notifications work for forks.
- A fix branch (eph-void-index) merged while this gate ran, so the KNOWN line the brief said to keep was stale by the end; check `git fetch` again after the gate, before marking.
