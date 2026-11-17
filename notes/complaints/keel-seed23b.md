# keel-seed23b
> Summary: Mishaps met while fixing full-size seed 23 (a removed store never moved past its keys).

- `wt claim keel-seed23b origin/main` gave c0b3a99f6 while the main checkout's `main` was older (2a63da78d): the gitStatus snapshot named the stale local main, not origin; check `git log -1 origin/main` before assuming a base.
- `git checkout <rev> -- core/engine/src` to replay on an older engine also reverts uncommitted edits under that path (lost a citation fix, redone): commit first.
- The why-kept diagnostic said why node 2 held thing 1 (an `unread` context from a stale sync ticket) but not why its store never stopped; the cause (a reader's filter never showing the store's step) took a hand `eprintln!` in `Opens::test`. A trace line for a Hit tested and not in the peer's filter would have shown it at once.
