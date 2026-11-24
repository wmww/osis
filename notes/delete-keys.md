# Delete keys
> Summary: How the engine lists and checks delete keys (spec/crypto.md §7; `sync_ids::steps`): a level-1 or level-3 key is a step key of a base's sync ID, listed from the newest step the base's `sync.0` records and checked per (commit, thing) against the steps placed from held valid `sync.0` state; a part listing a key no held step places is unjudgeable, never invalid; `sync.0` is a role part, so whoever opens a thing's role parts opens its steps; what re-judges what, why the verdict is per thing and takes any base up the record chain, and the one Interim site (a writer recording no step lists from its held secret or the published keyset).

**Principle: a key is right iff a step places it, from what is held.** A level-1 key is the delete key and a level-3 key the write key of a step on a verified path from the genesis step of a sync ID that a thing up the delta's thing's record chain records, each step recorded by a valid `sync.0` write stamped before the commit; a key-actor base's is its signing key. No secret is read and nothing is remembered: every node holding the same writes places the same keys.

## Listing (`CommitSecrets::key`, `Core::listed_step`)
The delete base is `Core::delete_base` (its independent: the nearest independent thing up the record chain, or the key actor ending it). Its step is the deepest placed step (ties by lowest ID) of the greatest sync ID it owns here (a step of it bears a sync key of a held sync secret; every placed one while no sync secret of the base's own is held). A commit making a thing independent lists its former base's keys: its own step is recorded by that commit, not before it.

## Placing (`Indexes::steps`, `steps::Recorded`)
Derived from the `sync.0` state at every write of it (`Tx::derive`; again at open), so from the held valid writes alone, a role compaction's snapshot included (a carried step entry keeps its recording write's stamp). Per step: its keys, depth, and `since`, the latest stamp on its path. A step verified once is not verified again (its ID commits to its bytes and parent). Not persisted.

## Checking (`Core::wrong_keys`, `Indexes::miskeyed`)
- **Per (commit, thing)**, not per commit: a node holding one thing's evidence cannot judge the keys a commit lists for another thing, so "invalid whole" would differ between nodes. A thing whose record chain is not known to its key actor is not judged (nothing on it applies meanwhile).
- **Any base up the chain**: derived-era content lists the former base's step, and so does a writer that has not received the commit making the thing independent; the nearest base alone would invalidate every write such a writer makes offline. A thing's own readers could tell only from what the writer knew, which no header says.
- **Any sync ID a `sync.0` records**: ownership turns on held secrets, a verdict must not.
- "Before": `since` < the commit's `ts`.
- Persisted as bit 7 of each part's byte in the commit's parts row. Judged again (`Core::rekey`) when the base's placed steps move (`steps_recorded`: a step added re-judges only the commits held as wrong under it; a step gone, every commit on a thing under the base), a record up a chain arrives (`timelines_changed`), or an account's held epochs move (`rejudge_once`). A verdict that moves names the commit stale and has a role commit's edge writes read again (`Indexes::rekeyed`).
- Debug builds compare the stored verdict with `wrong_keys` at every re-judge and at the end of each engine's history (`validity::misjudged_one`).

## What a verdict does (`Core::miskeyed`)
- **Not right is unjudgeable, never invalid** (spec/commits.md §4 Unjudgeable; `apply::unjudgeable`): a node cannot tell a wrong key from a step whose `sync.0` write it does not hold (a thing may have been made independent by a commit not here yet), so a miskeyed part applies nowhere (`Judge::part`, `add_role_commit`: its edge writes read by nothing) and is neither dropped nor forgotten as invalid: it is judged again when the steps, a record or an account epoch arrive (`rekey`). Judged invalid, a content header arriving before its thing's `sync.0` would be dropped and forgotten for good, and a reader would lack a must-hold body. A rule keyed on "a base known independent here with no genesis step" has the same hole: independence and the genesis step come in one commit.
- **The steps ride with the role parts** (`osis_keys::UNDER_ROLES`, spec/crypto.md §4 Roles secrets): `sync.0` is sealed in the roles section, so a node opening a thing's role parts in a shared blob opens the steps that judge them, whether or not it holds the thing (spec/sync-judgement.md §1 Sealed sections); on a thing outside the unit they ride as certificate copies by the derivation (`evidence::Reason::Step`). A link's redeemer reads K's role parts before K is in its node closure: with `sync.0` in the content section it would hold K's `keys.0`, `roles.0` and `secrets.0` and no step, and every key of K would read as wrong.
- A fire from outside lists the keys of the keysets of the inbox's `keys.0` its sender holds (spec/sync-inbox.md §2): right once a step bearing them is recorded before the fire (issues/delete-key-levels-unchecked.md, Left: a keyset published before its step).

## Interim (issues/delete-key-levels-unchecked.md)
- A node recording no step of the base lists the step key its newest held secret of the role derives, else the one the base's `keys.0` keyset publishes (`published_keys`; the keyset's `delete_key`). The published key is what the spec has an outside fire list; the held-secret fallback goes once no writer lacks its base's `sync.0`.

## Tests
- Hand-built commits take their secrets from `Engine::hand_secrets(records)` (`HandSecrets`): each thing's dedup secret and the keys the engine asked lists (ask the thing's maker), made up where it lists none, at level 2, and whole with `all_made_up()` (a forger's keys). A hand-built commit is stamped after the write recording the step it lists.

## Signing a Delete
A holder tries every held epoch up the thing's record chain (`Core::delete_chain`, `delete_secret`) and signs with the one whose step key the header lists (`DeleteSecret::at_level`).
