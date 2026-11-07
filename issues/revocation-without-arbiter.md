# Revocation without an arbiter
> Summary: Experimental plan, to be modelled before any spec or code change: a removal is written at once listing what the remover has seen; writers that saw the removed holder's content edits before the removal later attach addenda listing them, so an edit survives if any writer saw it in time. Role writes stay judged by the remover's list alone.
> Priority: normal
> Tags: permissions, sync, spec, tess-call

## Problem
A removal of Bob carries a frontier: the commit IDs of Bob's writes the remover had received (spec/permissions.md §5.1). Every write of Bob's below the removal that isn't listed turns invalid everywhere. Bob's timestamps can't decide (he could backdate). So the result depends on how well the remover's node had synced, and no node can know it has everything. Worst case: a group the remover never synced (or that only Bob and Carol sync) loses all of Bob's uncompacted history (§5.3 says so). Re-grant restores it, but also restores anything bad he wrote.

Today `set_role` first catches up with whoever is reachable; `set_role_now` doesn't. This narrows the loss but can't close it, and makes removal slow by default.

## Plan (experimental)
Everything below is a hypothesis to test, not a decision.

### Addenda
- Every node already records when it received each commit (`Meta::received`).
- A removal lists Bob's commits the remover has received, as today, and is written at once.
- **Addendum**: a commit naming a removal and listing commit IDs. A writer node that holds commits of the removed holder it received before the removal's `ts` (its corrected clock) publishes one listing those not already covered.
- A content write of Bob's survives iff the removal or a valid addendum lists it (plus the existing rules: snapshots that vouch, re-grant).
- This covers removing Bob from a group this node never syncs, as long as some writer that syncs it is online at some point; until then Bob's edits there are hidden.

### Rules that keep it safe
1. **Only writers vouch.** Readers and blind hosts don't: a demoted-to-reader Bob would vouch for his own backdated edits, readers write nothing today (a reader addendum needs a new reader-writable aspect, reader uploads at hosts, and frontiers on reader removals), and rule 3 has no meaning for a node that can write nothing. A host that is a writer's node vouches like any writer.
2. **After the removal, about earlier commits.** An addendum counts only if ordered after the removal it names, and lists only commits ordered before it. Otherwise a removed writer backdates an addendum to before its own removal (when the timeline says it wrote), and two removed writers vouch for each other in a cycle.
3. **Vouch only for what you could write yourself**, at the addendum's key in the role timeline: write on the thing, and also on the commit's header actor when the commit acts for one (§5.2 Acting); else a writer plus an ex-member of a team account write as that account.
4. **Plain content only.** An addendum lists no role commit and no role-class aspect (`roles.0`, `secrets.0`, `keys.0`, `label.0`), nor admin-only aspects. Role commits mix edge writes with rotations and boxes, so vouching for part of one splits it (a valid rotation whose removal stayed dropped), and keys and labels feed back into the role layer. Third-party witnesses for role writes never settle (period-2 loops in about 14% of random histories; notes/permissions.md, Role timeline). A removed admin's unseen grants still drop; re-grant fixes it.
5. **An addendum is an ordinary write of its author**, on an aspect of the things whose writes it lists, so a later removal of its author audits it like any of its writes. Judged as a least fixpoint seeded by writes valid without any addendum.
6. **Re-cover when coverage falls.** A writer that skipped an addendum because another already listed a commit publishes when that other addendum stops counting.

### API
- `set_role` writes at once and is synchronous; `set_role_now`, `revoke_link_now`, `kick_now` and CLI `--now` go; `remove_node` stops waiting.
- Docs say: usually call `db.wait_synced(SyncScope::Thing(target))` first, with a timeout, falling back to removing anyway on timeout or `Unsynced`. That syncs with saved peers, so edits that reached only a reader or blind host count. Edits held by other writers need no catching up: their addenda cover them.

### What stays lost
- An edit of Bob's that no writer received before the removal and that the remover didn't wait for: on an offline device, or at a reader or blind host only.
- Bob's purges of his own messages (`author` retention): no witness holds that right.
- A removed admin's unseen role writes, until re-grant.

### Open questions
- **Re-removal**: when Bob is re-granted and removed again, do the first removal's addenda still count, or must witnesses vouch again (§5.2 judges by the newest demotion)? Leaning: they still count.
- **Listing**: does the removal keep leaving out commits its compaction could drop (today's rule)? Affects cost on kept history and issues/frontier-certificate-cost.md.
- **Paging**: the remover can page long content lists as its own addenda (issues/unbounded-frontier.md), but the role part of a frontier can't move into addenda and still needs its own paging.
- **Wire form**: commit kind or aspect (rule 5 needs it on an aspect of the covered things), retention (dead once every listed commit is covered or dropped), one addendum per label (one spanning labels leaks commit IDs across them).
- **Duplicates**: writers seeing a removal together each publish nearly the same list (up to N writers × M commits); needs a back-off or jitter rule.
- **Invalid bodies must be kept** while a late addendum can still arrive; check what hosts and nodes drop today.
- **UX**: a removed member's edits can reappear when an offline writer syncs weeks later; apps may want to show which addendum saved a write.

## Validation
Before any spec or code change:
- **New content model** in `core/test/roles-model`: multi-author, driven by `joint.rs` timelines, random and exhaustive search (`src/content.rs` is scenario tests for one author, no search). Check:
  - one validity result for every arrival order of removals, addenda, later removals of witnesses, re-grants and re-removals;
  - adding a valid addendum never turns a write invalid;
  - the least fixpoint terminates and matches across nodes holding the same commits.
- **Role layer unchanged**: every existing layer-1 search and scenario gives the same results.
- **Attacks gain nothing**:
  - reader or blind host addendum;
  - writer vouching for role-class, admin-only or purge writes;
  - vouching for part of a role commit;
  - vouching for a commit acting for an actor the witness can't write as;
  - removed writer's backdated addendum, two removed writers vouching for each other;
  - addendum listing a commit ordered after the removal;
  - a witness lying about receipt time gains no more than its own write power (receipt time is local and unprovable).
- **Expected outcomes**:
  - Alice removes Bob without syncing a group, Carol later vouches, Bob's edits there return everywhere;
  - an edit no writer saw stays invalid;
  - skip-then-coverage-falls: Carol re-covers after Dave's addendum stops counting;
  - re-grant still restores everything.
- **Dropped data**: in the engine order oracles (`alike_exchanged`, notes/convergence-study.md), an invalid write turning valid after some nodes dropped its body converges once a holder uploads it.
- **Cost**: addenda per removal with duplicates, bytes per listed commit, where they replicate, against today's frontier.

If it holds: update spec/permissions.md §5.1–5.3, §6 (who may undo a purge) and spec/requirements.md Permissions; build with osis-perm checked against the model; integration tests for the expected outcomes.

## Current code
- `set_role` / `set_role_now`, `revoke_link` / `revoke_link_now`, `kick` / `kick_now`, CLI `--now`; catching up is described in notes/api.md (Demotion and catching up).
- Known gap there: a reader that dialed this node isn't checked when catching up, so a direct link's maker catches up with nobody. Moot under the plan.

## Decided for the model (Tess)
- Invalid bodies follow normal retention and may be dropped, even at once. A node receiving an addendum fetches the bodies it lists from the node that gave it (the witness held them when it wrote the addendum) or from any holder; a body no node holds stays lost.
- Monotonicity is a pass/fail check: an addendum never turns anything invalid, including through a later removal of its author.
- No rule 6 or back-off: every writer publishes its own addendum for everything it saw that the removal didn't list, whatever other addenda say (duplicates are a few commits in the common case).
- The unsynced-group case is protected only by the API's "wait first" advice; say so plainly.
