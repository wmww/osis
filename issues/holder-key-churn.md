# A holder's readers download every box of it
> Summary: A cost no reader needs: every reader of a thing fetches every box of each of its rotations (a removal from m holders costs the network m squared).
> Priority: normal
> Tags: sync, engine, keys

1. **Every box to every reader.** A rotation's boxes page (spec/crdt.md §8), and a commit applies only once every page is fetched. Nesting (spec/requirements.md Generality) cuts m per level and leaves the top level's rotation to every member.

Directions (design work, model first):
- A node that may not rotate a thing applies its rotation with only the pages holding its boxes (unfetched pages are a may-hold state, spec/sync-judgement.md §2); what rotators, re-sealers and the stale-box rules read of the other boxes decides how far this goes.

## Baseline
Measured in the engine (the commits of `grant`, `demote` and `ensure_rotated` packaged as `thing_cost::what_a_reader_costs` packages its grant: holder H with m writer members, H write on X, X's roster its admin and H; sync entries and stamps not counted), with notes/thing-cost.md:

| event | bytes | who downloads it |
|---|---|---|
| a member granted on H (read) | one commit, 4.0 KB | every reader of H; nothing below H |
| H granted write on X (granter holds H's secret: symmetric boxes) | one commit, 2.1 KB (`secrets.0` 1.15 KB) | X's syncers |
| a member removed from H | H's rotation: 2.7 KB + 4.9 KB per remaining writer (12.5 KB at 2 holders, 32.2 KB at 6; a reader's boxes are 2.7 KB) | every reader of H, every box of it (a commit applies only with all its pages, spec/crdt.md §8) |
| H's content changes | the change | every syncer of H's sync ID, path users included |

So with m members and k independent things below H, one removal costs, by design and before any change here:
- **H's rotation, in m**: 52 KB at 10 members, 4.9 MB at 1,000 (2.7 MB if they only read), downloaded by each member: m times that across the network. Claims page (spec/wire.md §5 Claim pages), so nothing caps direct members; nested three deep at fan-out 47 a removal costs every member the top rotation (about 230 KB), and the members of the two holders below it theirs.
- **A rotation of every thing below H, in k**: lazy (stale boxes, spec/crypto.md §4), 11.7 KB or more each, required for confidentiality (spec/requirements.md Cost: "in proportion to the rosters of what it could read"). Fundamental; candidates are judged against it.
