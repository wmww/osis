# Signal edits: design
> Summary: Design (Fathom, with Tess's direction: full replace only, reuse what osis has): an edit is a whole fire naming the fire it replaces, honored only for the same verified author. Spec terms, what is reused, API, costs, build plan.

**Verdict:** an edit is a whole fire that names the fire it replaces, and the fire's commit is its address. The register's rule is reused, but not the register state. I built nothing and changed nothing in the repo.

## Design (spec terms)
- **Claim:** header aspect entry gains optional `replaces: commit_id`, durable signals only. A relay-only commit carrying it is a bad part.
- **Honored**, judged from headers alone, when the named commit O:
  - is listed on the same `(t, ak)` and valid (a purge tombstone counts);
  - has no `replaces` itself (flat, no chains);
  - has the same verified `actor`;
  - sorts before the version by `(ts, ID)`.
- **Otherwise** it is a fire of its own, at its own place. A forged edit is just the forger's own message.
- **Read:** an original's part reads as its newest listed honored version by `CommitPos`. Stamp, place and order stay the original's, and honored versions are not listed separately.
- **One rule covers the required cases:**
  - edit turned invalid or expired: unlisted, so the previous version shows;
  - purged newest version: a listed tombstone, so nothing older comes back;
  - O invalid: its versions are unlisted;
  - O re-validated: they return.
- **Expiry:** a writer gives an edit O's `expires`. A required rule's check for a `replaces` delta becomes `ts < expires <= ts + duration`, so one is still required. O and its edits end together. An over-long edit stands alone once O goes, which is no more than a new message could do.
- **Retention:** each version carries its own, under the same required rule. Keep bounds and `keep_history` apply per version, from its own `ts`. Durable signals keep their history unchanged.
- **Old text gone:** the edit commit carries an ordinary purge request naming the earlier versions. The rule "no `expires` on a purge commit" becomes: a request reaches only deltas expiring no later than its commit, and the purge floor ends at that expiry. That restriction is what forced chat's second commit.
- **Edits off:** new `final` flag on a `required^.0` entry. A `replaces` delta breaks it and is invalid, judged per key like every required rule.
- **Limit:** a node that never held O's header (a finite-keep, non-expiring signal whose O was purged or aged out) shows the version alone. Permanent deltas keep lasting headers, so chat is unaffected.
- **Ephemeral signals:** no edits, refused with `Invalid`. Nobody holds the original, so there is nothing to replace.

## Reused and new
**Reused:**
- register order (newest wins);
- purge requests and tombstones;
- required rules;
- validity (`actor`, key order), so removal needs no new work: an edit after a kick is invalid and not honored;
- retention and expiry per delta;
- the listing rule and `on_fire`.

**New:** the header field, two index sets, the fold in listings, `replace`, the `versions_of` filter, `CommitFrom::At`, and `final`.

**Rejected:**
- *A signal as a map or register state* (`winners`, `carried`). Joining would make validity flips rebuild state, and signals are unjoined so a kick rebuilds nothing. `winners` has nothing to judge.
- *`purge on replace` retention.* It works through compaction covers, which signals have none of. It needs `writer`, and it isn't "permanent", so headers (and the original's place) would be lost at new nodes.
- *`undoes`.* It is commit-level and open to any writer. Edits would pollute `reverts` and kit's undo. An edit is not an undo.

Undo stays as it is: an undo of a signal writes nothing back. To restore text, replace again.

## API
No schema opt-in: only your own fires can be replaced, so it harms nobody.
```rust
w.at(c, MSG).fire(&msg)?;                                  // send
w.at(c, MSG).replace(m.pos(), &edited)?;                   // edit, keeps versions
for v in old { w.at(c, MSG).purge(Purge::Commit(v))?; }    // same commit: old text goes
let p = k.at(c, MSG)?; // p.body newest; p.edited: Option<CommitPos>; k.stamp the original's
db.at(c, MSG).fired(&CommitQuery { from: CommitFrom::At(id), limit: Some(1), ..Default::default() })?; // quote
db.at(c, MSG).fired(&CommitQuery { versions_of: Some(id), ..Default::default() })?;                    // versions, own bodies
```
- **`on_fire`:** an edit is heard as `Commit { id: original, commit }`, because the original's listed form changed. A version not yet folded is heard under its own id, then `None` when O arrives.
- **`CommitFrom::At`:** inclusive place, replacing the `After(time)` walk.
- **`final`:** `Required { retention, expires, final: true }`.
- **Reaction:** `chat:react~0: { target, emoji: option<string> }`. `replace(r, {target, emoji: Some(new)})` changes it, and `emoji: None` or a purge withdraws it. Finding reactions by message is a separate listing question.

## Costs
Totals are at n and 10n messages, with v versions on a message.

| Operation | Today | Design |
|---|---|---|
| Edit | 2 commits, plus a walk | 1 commit, O(log n) |
| Listing page p | Distance from newest | O(p log n), one body per entry |
| Quote | History since it | O(log n), one body |
| Kick | Per surviving message and version | Same (the frontier is per commit) |

Index: `originals` for paging (honored versions removed, so edits add no walk) and `versions` keyed `(t, ak, O, actor)`, valid only, so forged claims are never read. Both move on validity flips inside the existing rejudge, and O's arrival promotes matching versions.

**Removed from osis-chat:** `Timeline`, `find`, `find_all`, `edit_of`, `Claim`, `checked`, `entry_at`, `prior`, `Message`'s fold and its `earlier`, the schema's `edit` field and `edit` struct, the second purge commit, and the `edit` mode in settings (it moves to the required rule). `since` stops folding.

## Build plan
Each step gets one worker and one reviewer.
1. **Model first.** A small TLA or held-model covering arrival order, validity flips, purge, expiry and forged claims. Properties: nodes holding the same commits read alike, and a forged claim changes no reading.
2. **Wire and rules:** `replaces`, the honoring rule, `final`, the expiry bound, the purge and expiry change; spec/commits.md, spec/wire.md, spec/data-model.md.
3. **Engine indexes and fold:** `originals`, `versions`, listing, listener events. Counted test at n and 10n: bodies read per page and per quote are flat.
4. **`osis` API:** `replace`, `versions_of`, `CommitFrom::At`, port, CLI, compile-fail doc tests; api-design checklist.
5. **Chat and app:** delete the list above and quote by `At`. This delivers fast-design step 9.

## For Tess
- **Requirements line:** "A signal has no current value, only entries" would gain "an entry can be replaced by its author". A signal still has no current value, but this is a change to the requirements, so it needs your OK.
- **Disappearing chats:** an edit does not extend the timer, it ends with the original. Say if you'd rather an edit restart it.