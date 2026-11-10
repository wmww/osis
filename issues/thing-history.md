# History and expiry defaults are a thing's setting
> Summary: Design study (Tess's proposal): history is set per thing by its admins in one admin-only aspect `retention^.0` (per aspect key: keep window, keep-until, or purge on replace; plus the expiry default a writer fills in), judged from the settings held; per-write history, `required^.0` and schema history defaults go. Rules, costs, what goes, the model and its result, build steps, and five decisions for Tess.
> Priority: normal
> Tags: tess-call, retention, spec, engine, sync, api

**Blocked on Tess**: the design is sound and modelled, with a default chosen for each open point, but five decisions are hers (Questions for Tess). Not to be implemented before her go-ahead.

## Principle
A thing's admins decide what replaced content is kept and shown, and for how long; the setting never decides who may drop a body (purgeable-by, per write) nor deletes anything promptly (purge, expiry). Every judgment reads only the settings and bodies a node holds.

## Rules
### The setting
- `retention^.0`, admin-only, on the thing it governs. Value: `rules` (AK to entry), `default` (an optional entry) and `retain` (the removal default, spec/permissions.md §2). An entry: `history` (absent: no history promised; `keep { after D, until T }`, at least one; `purge_on_replace`), and `expires` (an optional duration, Expiry default).
- The entry governing an AK is its own in `rules`, else `default`; neither: no history promised, no expiry default.
- Fixed retention: `nobody`, never out of history, never snapshotted, never undone, written whole, each delta read alone as the whole setting. A delta not reading as the type, with a key that is not an AK or past `MAX_RETENTION_ENTRIES` is no setting. It carries no `expires` and goes with a commit of any purgeable-by, as `required^.0` does.
- It governs every aspect of the thing but those with fixed retention (role-class, `addenda.0`, `purge.0`, itself), memory aspects included.
- A delta is judged as an admin-only delta at its key (spec/permissions.md §5.2). Validity of no other delta depends on a setting.
- **In force**: the held valid settings ordered by key are the thing's timeline. At wall time t the setting in force is the newest by key with `wall_ms(ts) <= t`; before the first, the empty setting. A setting is in force from its own commit on, so a creating commit's setting covers that commit's writes.
- **One way** (question 3): where an earlier setting of the timeline governs an AK with purge on replace, a later `keep` entry for that AK reads as no history promised.

### History
- **Replaced at** r: unchanged (spec/commits.md §5 Bodies and deaths): a value body at the `ts` of the earliest held valid body holding a superseding write; a signal's body at its own `ts`; a purged part, for listing, at its request's `ts`. Holding more bodies dates no later.
- A setting **keeps** a body at time t while t < max(r + D, T) under a `keep` entry (a missing bound counts as 0); never under no entry or purge on replace.
- A body **leaves history** at the first t >= r at which the setting in force at t does not keep it, and is out from then on. A body whose purgeable-by is `nobody` never leaves (question 2).
  - So a setting acts from its own stamp: it can shorten or extend the window of bodies still in history at that moment and reaches nothing that left before it. A body replaced before any setting, or under an entry with no history, is out when replaced.
  - Bodies of one aspect leave in the order they were replaced: one threshold per (thing, AK) at any moment.
- **In history**: a held valid replaced body that has not left, by the node's corrected clock. That, and the parts live in the state, is kept history: what listings show (§7 Listed parts), what undo writes back from, and what `history()` reads. A body out of history is not listed, held or not.
- **Keep at least**: before a body leaves history (`MAX_DRIFT` past, on the node's clock) compaction and own replaces MUST NOT drop it, right holders MUST NOT delete it at hosts, and it is kept for must-hold (spec/sync.md §6). Purge requests and expiry act whatever the window; invalid bodies drop as today.
- **Out of history**: a value body drops as today, as covered by a cover holding the right (Between the bounds); a signal's body may be dropped by any node. A node takes no copy of a body that is out, fetches none and holds none as must-hold.
- **Dropped stays dropped**: a body a node dropped as covered or as out of history is not missing when a setting that arrives later puts it in history. An extension reaches what a node still holds.
- Compaction snapshots carry `writer` and are judged by the setting like any body; replaced at the latest death among the writes they carry that no later held valid snapshot carries.

### Purge on replace
- A body is **under purge on replace** when the entry governing its AK in the setting in force at its replaced-at is `purge_on_replace` (never a `nobody` body, never a signal's: there the entry reads as no history).
- The duty and the drop are spec/commits.md §5 Purge on replace with that test in place of the delta's own mode: a node that may write the aspect and holds such a body, replaced, that no held valid snapshot holding the right covers, writes a snapshot from its whole state in the transaction in which that comes to hold (the replacing write, the body, a validity or role change, or a setting arriving or changing validity); every node drops such a body once a held valid snapshot holding the right covers it.
- No writer is invalid for not knowing the setting: the duty falls on every writer that holds the replaced body and the setting.
- Content replaced before the setting's stamp is out of history from that stamp with no purge promise.
- A cover drops only bodies its commit holds the right over, as any cover (question 4): a writer writes `writer` on an aspect under purge on replace.

### Signals
- A fire is history from its own `ts` under the entry governing its AK: no entry, no listing. A writer refuses a fire the setting it holds would not keep (`Invalid`).
- The wire carries no history, so the rule "a signal's retention is keep history" goes. `replaces`, honoring and listeners are unchanged; versions and their original share one window, each from its own `ts`.

### Listings, undo, permanence
- A purged part is listed while its value-less writes are in the state or a body replaced at its request's `ts` would be in history.
- Undo (§7): a part the undone part may have replaced is kept when it is in kept history, or the AK's bodies replaced at the undone part's `ts` are in history now (one check per aspect, not per part), or a kept part supersedes it.
- A delta is **permanent** when it is durable, not fixed-retention, without `expires`, and a body of its AK replaced now would never leave history (a forever entry, or `nobody`). Lasting commits follow as today.
- `complete` is unchanged: it speaks of sync passes. History a node dropped before an extension reached it is absent there, not a gap.

### Expiry default (Tess decided)
- Expiry stays on the commit (§6). An entry's `expires` is the duration a writer fills `expires` from (`wall_ms(ts)` + duration), reading the newest valid setting it holds at write time; a schema default applies where the setting has none; a write may still set its own.
- A commit is valid with the expiry it carries, whatever the setting says or later says. A change reaches later writes only.
- One expiry per commit stands: a writer refuses a write whose parts would be filled with different expiries unless the write names one.

### Convergence
- Every judgment above is a function of the settings and bodies held and the clock; nothing is dated by arrival. Nodes holding the same bodies and settings show the same history.
- A late setting (stamped before ones already held) can move a body out of or back into history, where it is still held; a setting that turns invalid was never in force. Both converge: the timeline is the held valid settings.
- No resend loop: a body out of history is neither must-hold nor fetched; one in history at a node that dropped it is not fetched. Two nodes disagree only while one lacks a setting, and settings are must-hold for good under the thing's labels; node-sync places before it deletes, so a label a right holder deletes at holds the settings it judged by.
- **Disputes**: each side's timeline is the settings valid under its trust set. A side that does not count a setting keeps and shows what the other side may drop; right holders delete a covered body at hosts once per body as today, so the sides do not chase each other. Sides that later agree judge alike, with what is still held.

## Security and promises
- Keep is a promise only by nodes that hold the setting: a node drops nothing in history by its own held set. Purge on replace keeps its property under late dating (model: content replaced under it is never history, however a node dates the replacement) because of the one-way rule.
- An admin can, beyond purge: stop honest nodes showing the history of writes it holds no purge right over (`author`), let right holders compact it, and let any node drop a signal's entries. It cannot touch live values, `nobody` bodies, or force a prompt deletion. Backdating gives nothing more: a setting stamped in the past ends at most what a setting stamped now would, and re-shows only bodies readers still hold. A removed admin's setting is invalid as any admin-only write is.
- A writer ignoring the setting can only give its own writes another expiry or purgeable-by.

## Cost
- A setting change: O(settings of the thing) to rebuild the timeline, plus what leaves or is owed. Nothing is re-judged for validity (today a `required^.0` change re-judges every later delta of the thing).
- Index: the timeline per thing (`ix.retention`, as `ix.required`); per (thing, AK) one timer at the next leaving, since bodies leave in replaced order. Signals need no rows (the listing is in `ts` order: the threshold is a range bound); value parts keep one row (thing, AK, replaced-at, commit) written where `T_KEPT` timers are armed today. A window passing costs the parts that leave, each once; reads and compaction O(log settings) on top of today's replaced-at.
- Turning purge on replace on: one snapshot per governed aspect holding replaced content, at each writer; then as today.
- Growth: one setting delta per change, for good (a few hundred bytes; replaces the `required^.0` row), and one per thing that wants history or undo, where a schema default cost nothing per thing. Per-write: the aspect entry loses its history field; a signal body's timer row goes.

## What goes, stays, becomes
- **Goes**: the wire's `history` in `Retention` (it is `by` alone) and the ephemeral marker's history clauses; `required^.0`, its validity rule (spec/permissions.md §5.2), `MAX_REQUIRED_ENTRIES`, `Required`/`RequiredRules`; schema `keep_history` and `purge_on_replace` on aspects; snapshot retention inherited from carried writes (`own_retentions`, `cannot_keep`, the "with at least its D" clause, mixed modes on one aspect); per-body signal timers; `KeepRule` per header; the zero-growth limit "a required rule invalidates both covers" (issues/zero-growth.md); issues/delete-required-rules.md (a delete answers to no rule); held-model `History`, `snapshot_retention`, `Delta::Required`.
- **Stays**: purgeable-by per write with schema defaults; expiry per commit; replaced-at; covers, own replaces and forgetting (a commit goes once every part is out of history); purge, purge floor, leftovers; `ROLE_KEEP`; R1 and suspect repair.
- **Signal edits**: honoring and versions unchanged. `final` has no validity rule to live in: the default here is a flag on the entry that only the writer reads (`replace` refuses), question 5. The limit "a purged edit with a shorter keep lets older versions show again" goes (one window per AK).
- **Chat**: `create` writes `retention^.0` (`chat:msg~0`: keep forever, `expires` the disappear timer, `retain`). The timer is a default: a message expires as its sender saw the setting; a stale or modified client's message keeps the expiry it carries. The purge option is filled per write by the chat library from its own setting (question 5).
- **Purge on replace in requirements**: the promise and its cost line stand, "while the setting is in force" added, plus the one-way limit.
- **Ending** (notes/expiry-creation-design.md step 8): ending drops the thing's settings and history with every other part; role history kept for dependents is fixed retention and not governed. An expiring creation cannot carry the setting (it has no `expires`): two commits.
- **App layer**: kit and app write the setting where they create things that want undo (today's `keep_history(1d)` aspects); without it a replace is not undoable.

## Model
`core/test/held-model/src/thing_history.rs`, `tests/it/spec_thing_history.rs` (9 tests, pass, 2 s): over every timeline of up to three settings on stamps 0..7 and six options: bodies leave in replaced order; a setting stamped after a body left never brings it back; a later setting acts only from its stamp; a late setting can re-show a held body (stated behaviour); purge-on-replace content is never history however late dated, and is without the one-way rule (the counterexample is a test); `nobody` never leaves; a node dropping at the first allowed moment shows what a keep-everything node shows when nothing is late, a subset in every arrival order, and lacks only what it dropped itself.
Not modelled: covers and rights (unchanged rules), validity flips of settings (the timeline is "valid held"), host placement.

## Questions for Tess
1. **"Never comes back" is true of the timeline, not of each node.** Case: a node holds a body, judges it out, and then receives a setting stamped earlier that keeps it: it shows the body again if it still stores it. The alternative is a per-node mark "left here", which makes what a node shows depend on arrival order (against Deterministic). Default: the timeline rule.
2. **What shortening needs.** (a) Admin alone, every body: simplest, but a `nobody` body is then hidden yet can never be dropped, and admins can end `nobody` signal entries. (b) Admin alone, `nobody` bodies never leave history: today's sentence "a `nobody` delta keeps history forever" stays, nothing is stored unshown. (c) Purge right over each body: a carve-out; the window becomes per write and per setting author again, bodies no longer leave in order, and the one-timer index is lost. Default: (b). Under (a) and (b) an admin can still end the history of `author`-only writes it could not purge.
3. **Purge on replace, then keep.** Case: an aspect purges on replace, then is set to keep. A node that was away still holds content replaced meanwhile; the replacing write is purged everywhere, so the node dates the replacement by a later write, inside the keep era, shows the purged content as history and uploads it to new nodes. Options: (a) one way: once purge on replace was set for an aspect of a thing, a later keep there keeps nothing (model-checked); (b) state it as a limit; (c) judge by when each write was written, per write: complex, and a stale writer's snapshot still carries it across. Default: (a).
4. **Purge on replace and writes only their author may purge.** A cover drops only what its commit may purge, so a write carrying `author` or `admin` on a purge-on-replace aspect stays until such a holder covers it. Options: (a) stated limit, writers fill `writer`; (b) out of history, any valid writer's cover drops a body at every node (see 6). Default: (a).
5. **What `required^.0` did besides history and expiry.** It forced who-may-purge per AK and edits-off (`final`), by making other writes invalid. With no setting touching validity these become defaults a writer follows, like expiry: a modified client can write `nobody` content admins cannot purge (already so on any thing without the rule), or edit its own message in an edits-off chat. Options: (a) defaults only; (b) keep a small validity rule for who-may-purge alone; (c) edits-off as a reading rule (an edit stamped while it is on is not honored and shows as a new message). Default: (a).
6. **Requirements wording** (yours). Proposed:
   - Deletion, first item: "Who may purge an edit is set per edit (nobody, admins, the author, the author or admins, any writer): a default per aspect, overridable per write, immutable once written. What happens to replaced content is set per thing and aspect by the thing's admins and may change at any time: by default nothing is promised; kept at least a while after it is replaced and/or until a time; or purged once replaced. A change reaches the history nodes still hold: what has left never returns, and a longer window brings back nothing a node already dropped. A default expiry is set the same way and is only what a writer fills in: an edit keeps the expiry it was written with."
   - In place of "A node without write on data deletes it on its own only at expiry...": "A node deletes data on its own only where nothing promises to keep it: at expiry, and history its thing's settings no longer keep. Purging is the act of a right holder, taking effect elsewhere when it arrives."
   - That sentence fits signals as built. For replaced values it holds only if a node may drop a body out of history once any valid writer's compaction carries what is still current, without that writer holding the purge right; today such bodies stay at readers for good (issues/zero-growth.md Left). Say whether "data not promised is not kept for good" should become a rule: it also settles question 4 as (b).
   - Purge on replace: add "set per thing and aspect, for content replaced while it is set. Limit: an aspect that purged on replace keeps no history on that thing again."

## Steps
Each one worker and one reviewer, in order; main stays green after each.
1. **held-model.** `Retention { by }`; `Delta::Retention` settings and the timeline; `history`, fates and `owed` from `thing_history`; `History`, `snapshot_retention` and `Delta::Required` go; generator writes settings, late and invalid ones included. Tests: the props as they stand (function of the held set, forced fates change no read, any order), plus every `spec_thing_history` property through `evaluate`.
2. **One door in the engine** (behaviour-preserving): every reader of a body's history mode (bounds, listing, undo, replace, snapshot, node-sync's kept) asks one function of (thing, AK, replaced-at). Tests: none change.
3. **The setting.** `retention^.0` in the core schema and osis-commit (type, fixed retention, the pure `out` function matching the model), `ix.retention` kept on apply, validity flip and drop; the door reads it; the wire's history field, `required^.0` and its validity rule go; purge on replace by the setting with the one-way rule and the setting-arrival trigger; spec/commits.md §5-§7, spec/wire.md §4, spec/permissions.md §5.2, spec/data-model.md §2, §9, spec/sync.md §6. Tests (observable): history shown follows a setting in any arrival order; a shortening hides and a later extension does not bring back; a node that dropped before a late extension does not refetch; a late purge-on-replace setting makes holders cover; purge then keep shows nothing; a fire with no entry is refused and unlisted; two hosts, one lacking the setting: no upload-delete repeat; held.rs and the order oracle against step 1.
4. **Writers and API** (notes/api-design.md): expiry and `retain` filled from the setting; `Retention` without history, per-write history calls gone, `HISTORY`-style typed access to the setting; schema DSL keywords and `schema/*.osis`; chat, CLI, kit and app write settings at creation. Tests: a message expires as its sender saw the setting; undo works on a kit-created thing; compile-fail for the removed calls.
5. **Timers and index.** One timer per (thing, AK); signals by range; value rows by replaced-at. Counted at n and 10n: a setting change and a window passing read no body and walk no commit that stays listed.
6. **Notes and bookkeeping.** notes/engine-retention.md principle and modes, notes/growth.md rows, notes/signal-edits-design.md, notes/api.md; requirements wording as Tess signs it; close issues/delete-required-rules.md and the zero-growth limit line.
