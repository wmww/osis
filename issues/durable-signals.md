# Signals decoupled from ephemerality: durable signals
> Summary: A signal is an aspect with no current value, whose writes exist only as commits. A durable signal (`x~0`, schema keyword `signal`): each write a signed commit kept in history until expiry or purge, never merged, never in state. `x+~0` (`ephemeral signal`) is today's signal. The grammar has both; `x~0` parses and every write and schema refuses it ("durable signals are not supported yet"). Gives logs of authored entries (messages, comments, audit trails) a first-class form instead of a value nobody reads. Design and retention rule decided with Tess; to be modeled, specified and built. Afterwards nothing in text or code ties signals to ephemerality.
> Priority: normal
> Tags: crdt, sync, retention, schema

## Design (Tess)
Two independent markers on the AK:

| | keeps a current value | signal: no current value |
|---|---|---|
| durable | `name.0` (`aspect`) | `name~0` (`signal`, new) |
| ephemeral | `name+.0` (`ephemeral aspect`) | `name+~0` (`ephemeral signal`, built) |

- **Signal** (`~` before the version): a write is a whole-value set of the aspect's type, never joined into state; the aspect never reads as a value. Writes are delivered to listeners. A durable signal's writes are held, synced and readable as history like any durable body.
- **Ephemeral signal** (`+~`): today's signal, unchanged: once, to connected nodes, held by nobody.
- Why: an app that wants a log of authored, immutable entries (each verified by its signed commit, removable only by purge rights) uses history today and also carries a meaningless current value that merges concurrent entries and duplicates the latest one. A durable signal keeps the history properties and drops the value.

## Consequences to work out
- **Retention (decided, Tess)**: a signal write counts as replaced the moment it is written (there is no current value for it to remain), so it is history from the start and the history modes apply unchanged: `keep_history(D)` keeps entries readable for D after writing, `until T` and `∞` likewise (∞ is a permanent log). No history setting means no history available (the public API never exposes history not specified to exist), and `purge_on_replace` purges at once: both are an ephemeral signal without the marker, so a non-ephemeral signal must declare `keep_history` and the schema refuses one without it. Expiry and purge apply per write. Never covered (nothing to snapshot), so held until its keep bound, expiry or purge.
- **Validity** (spec/permissions.md §5.2): a validity flip (a kick) rebuilds no state for the aspect; it only changes which bodies read as valid in history.
- **Commits and sync**: storage class from the AK alone (spec/data-model.md §2, spec/commits.md §2). A durable signal part goes in durable content commits; snapshots carry none of it. Compaction never needs its bodies.
- **Undo** of a durable signal write: a purge of it, or refused. Pick one (spec/crdt.md §4.6).
- **Expiry** (spec/commits.md §6) applies per write.
- **Grammar**: done (spec/data-model.md §2: `["+"] ["^"] ("." / "~") version`; `Lifetime::DurableSignal`, refused at `Engine::write`, `Schema::validate` and by receivers as a bad part, spec/commits.md §2). Schema rules: "a signal AK declares no expiry" holds only for `+~`.
- **API**: the write op for signals (whole-value only), `on_event`, history reads; the API's current wording that ties signals to ephemerality (notes/api.md).
- **Growth**: a notes/growth.md row: durable signal bodies are kept by design, a permanent cost per write.

## Requirements (wording agreed with Tess)
Replace spec/requirements.md "Signals have no lasting value: they reach the nodes connected at the time, once, with no delivery guarantee, and are held by nobody." with, in substance: a signal has no current value; if it is ephemeral it is not persisted, so it reaches only the nodes connected at the time; otherwise its entries are kept in history as long as its settings specify. Avoid presenting "ephemeral signals" and "durable signals" as two kinds: ephemeral and signal are independent markers.

## Building it
1. Requirements wording (agreed above).
2. Model: extend held-model (and roles-model if validity changes shape) with a stateless durable aspect: its bodies' fates under purge, expiry, kicks and compaction, in any arrival order.
3. Spec: data-model §2 (markers), commits §2/§5/§6, crdt §4.6 (undo), sync (signals, snapshots), permissions §5.2 where validity reads state.
4. Build: lift the refusals (`Engine::write`, `Schema::validate`, spec/commits.md §2 storage class), codegen, engine write and apply paths, snapshots skipping the aspect, history reads, the osis API.
5. Tests: small tier-1 reproducers per property (never in state; never merged; kept until purge or expiry; a kick re-judges bodies without a rebuild; ephemeral `+~` unchanged), plus the per-branch oracles for retention and validity in notes/testing.md.
6. Then move chat's messages to `chat:msgs~0` (`signal`) and drop what the value forced on it (notes/chat.md).
