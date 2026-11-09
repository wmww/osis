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
- **Read:** an original's part reads as its newest listed honored version by `CommitPos`, valid versions only (a node's own invalid part is marked and reads as itself). Stamp, place and order stay the original's, and honored versions are not listed separately.
- **One rule covers the required cases:**
  - edit turned invalid or expired: unlisted, so the previous version shows;
  - purged newest version: a listed tombstone, so nothing older comes back;
  - O invalid: not honored, so a valid edit is a fire of its own at its own place, and an edit invalid with it is unlisted;
  - O re-validated: its versions fold under it again.
- **Expiry:** a writer gives an edit O's `expires`. A required rule's check for a `replaces` delta becomes `ts < expires <= ts + duration`, so one is still required. O and its edits end together. An over-long edit stands alone once O goes, which is no more than a new message could do.
- **Retention:** each version carries its own, under the same required rule. Keep bounds and `keep_history` apply per version, from its own `ts`. Durable signals keep their history unchanged.
- **Old text gone:** the edit commit carries an ordinary purge request naming the earlier versions, and stays honored. The rule "no `expires` on a purge commit" becomes: a request reaches only deltas expiring no later than its commit, and the purge floor ends at that expiry. That restriction is what forced chat's second commit.
- **Edits off:** new `final` flag on a `required^.0` entry. A `replaces` delta breaks it and is invalid, judged per key like every required rule.
- **Limits:**
  - A purge takes only the commits it names. A version racing a purge of O, or written after it, still shows (no more than a new message could do); a deletion meant to hold names the versions too, or purges by author on the aspect.
  - An original past its keep is not listed, so its versions stand alone at their own places. This happens at every node, also under one shared `after D`: O's `ts` is earlier, so it ends first. A node that never held O's header reads the same. Permanent deltas keep lasting headers, so chat is unaffected.
  - A purged edit with a shorter keep or earlier expiry than older versions lets them show again when its tombstone ends. Purging old text means naming the earlier versions in the same commit, which is what the API does; a schema wanting a guarantee uses a required rule.
- **Ephemeral signals:** no edits, refused with `Invalid`. Nobody holds the original, so there is nothing to replace.

## Reused and new
**Reused:**
- register order (newest wins);
- purge requests and tombstones;
- required rules;
- validity (`actor`, key order), so removal needs no new work: an edit after a kick is invalid and not honored;
- retention and expiry per delta;
- the listing rule and `on_fire`.

**New:** the header field, two index sets, the fold in listings, `replace`, `commit`, `versions`, and `final`.

**Rejected:**
- *A signal as a map or register state* (`winners`, `carried`). Joining would make validity flips rebuild state, and signals are unjoined so a kick rebuilds nothing. `winners` has nothing to judge.
- *`purge on replace` retention.* It works through compaction covers, which signals have none of. It needs `writer`, and it isn't "permanent", so headers (and the original's place) would be lost at new nodes.
- *A purge of O ends the message* (no version shows, even after the tombstone ends). It needs an exception for an edit's own purge of old text, and a reading that depends on a purged commit no longer listed.
- *`undoes`.* It is commit-level and open to any writer. Edits would pollute `reverts` and kit's undo. An edit is not an undo.

Undo stays as it is: an undo of a signal writes nothing back. To restore text, replace again.

## API
Built (notes/api.md Signals, Edits). No schema opt-in: only your own fires can be replaced, so it harms nobody.
```rust
w.at(c, MSG).fire(&msg)?;                                   // send
w.at(c, MSG).replace(id, &edited)?;                         // edit, keeps versions
w.at(c, MSG).replace(id, &edited)?; w.at(c, MSG).purge(Purge::Commit(id))?; // same write: old text goes
w.at(c, MSG).purge(Purge::Commit(id))?;                     // delete: the fire and every version held here
db.at(c, MSG).fired(&q)?;                                   // page: each fire under its id, newest text, `Part::edited`
db.at(c, MSG).commit(id)?;                                  // quote: Option<Commit>, O(log n), one body
db.at(c, MSG).versions(id, &q)?;                            // history: the fire then its replacements, each as written
```
- **One reading.** Every read of a fire (page, `commit`, `on_fire`) is the fold, so the ergonomic read is the fast one; history costs only when asked (`versions`). `Part::edited: Option<CommitPos>` is the newest version's place.
- **`replace(id, v)`**, not a `fire` modifier or a second commit: it refuses (`Invalid`) a replacement the writer would not honor (another's fire, a version, not held, invalid, ephemeral, `refuse_replace`), so no edit is ever emitted to stand as a stray new message. Its id is a version's, which no listing shows: the app keeps the original's.
- **`commit(id)`**, not `CommitFrom::At`: a quote's contract is one-or-none, not a page; `At` plus `limit: 1` would hand back the next message when the quoted one is gone, and an inclusive bound has no direction of its own. It works on any key (`writes` or `fired` address), for any "follow this id" read. Jump-to-message paging uses `Before`/`After` of its `pos()`.
- **`versions(id, q)`**, not a `versions_of` filter on `CommitQuery`: it changes what is walked and how bodies read (unfolded), and applies to `fired` only (a field only some calls honor). No `on_versions`: `on_fire` hears every change under `id`.
- **`Purge::Commit` of a fire takes its held versions** (the API names them in the request): the original's id names the message, so deleting it deletes all its text; the alternative, an app listing versions to purge, is a footgun (purge only the original and the newest edit still shows).
- **`on_fire`** hears an edit once, as `Commit { id: original, commit }`. A version arriving before its original is heard under its own id, then `None` when the original arrives. The engine tells a version itself only when it leaves or takes a place of its own (`edits::unheard`, from `originals`' journal).
- **`Required::refuse_replace`** is the wire's `final` (`final` is reserved in Rust).
- **Reaction:** `chat:react~0: { target, emoji: option<string> }`. `replace(r, {target, emoji: Some(new)})` changes it, and `emoji: None` or a purge withdraws it. Finding reactions by message is a separate listing question.

**Step 5 needs** (chat and app): reply targets and edit targets as the original's `CommitId` (today `CommitPos`); quote with `commit(id)`; show "(edited)" from `Part::edited`; edit by `replace` plus `Purge::Commit` in one write for purge mode (the `edit` setting moves to `refuse_replace` for off); delete by one `Purge::Commit`; history via `versions`; listen with `on_fire` only. `osis chat edit` and `delete` then sit on these calls; the generic CLI already has `fire --replaces C` and `fired --versions-of C`.

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
Each step gets one worker and one reviewer. Steps 1-4 are built: the model (`core/test/held-model/src/edits.rs`), the wire and rules, and the engine (`core/engine/src/engine/edits.rs`: `originals` persisted, `versions` derived from views and validity; `settle` re-places the claims of each changed original and each changed claim at a transaction's end; a purge tombstone's end has a `T_KEPT` timer).

- Listing is judged from headers (spec/commits.md §7): an original whose body is not here yet is listed (not fetched) and its versions fold under it; the read takes the newest version whose body is here (or purged). Engine and model alike.
- An original leaving the listing by time (expiry, keep bound, tombstone end) frees its versions when its timer runs. The node runs due timers before every API call (`expire_due`), as for expiry, so no call sees the gap; only a raw engine read between the bound and `tick` does.
- A claim sorting before its original is model-tested only: an engine test needs two devices of one account with skewed clocks.

1. **Model first.** A small TLA or held-model covering arrival order, validity flips, purge, expiry and forged claims. Properties: nodes holding the same commits read alike, and a forged claim changes no reading.
2. **Wire and rules:** `replaces`, the honoring rule, `final`, the expiry bound, the purge and expiry change; spec/commits.md, spec/wire.md, spec/data-model.md.
3. **Engine indexes and fold:** `originals`, `versions`, listing, listener events. Counted test at n and 10n: bodies read per page and per quote are flat.
4. **`osis` API:** `replace`, `commit`, `versions`, `Part::edited`, `refuse_replace`, port, generic CLI, compile-fail doc tests (API, above).
5. **Chat and app:** delete the list above and quote by `commit`. This delivers fast-design step 9.

## For Tess
- **Requirements line:** "A signal has no current value, only entries" would gain "an entry can be replaced by its author". A signal still has no current value, but this is a change to the requirements, so it needs your OK.
- **Disappearing chats:** an edit does not extend the timer, it ends with the original. Say if you'd rather an edit restart it.