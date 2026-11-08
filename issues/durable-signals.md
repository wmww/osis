# Signals decoupled from ephemerality: durable signals
> Summary: A signal is an aspect with no current value, whose writes exist only as commits. `*` alone becomes a durable signal: each write a signed commit kept in history until expiry or purge, never merged, never in state. `~*` is today's ephemeral signal. Gives logs of authored entries (messages, comments, audit trails) a first-class form instead of a value nobody reads. Design decided with Tess; to be modeled, specified and built.
> Priority: normal
> Tags: crdt, sync, retention, schema

## Design (Tess)
Two independent markers on the AK:

| | keeps a current value | signal: no current value |
|---|---|---|
| durable | `name.0` | `name.0*` (new) |
| ephemeral | `name.0~` | `name.0~*` (today's `*`) |

- **Signal** (`*`): a write is a whole-value set of the aspect's type, never joined into state; the aspect never reads as a value. Writes are delivered to listeners. A durable signal's writes are held, synced and readable as history like any durable body.
- **Ephemeral signal** (`~*`): today's signal, unchanged: once, to connected nodes, held by nobody.
- Why: an app that wants a log of authored, immutable entries (each verified by its signed commit, removable only by purge rights) uses history today and also carries a meaningless current value that merges concurrent entries and duplicates the latest one. A durable signal keeps the history properties and drops the value.

## Consequences to work out
- **Retention**: a durable signal body is never covered (nothing to snapshot), so under the retention principle (every drop that is not expiry or purge is a covering snapshot) it stays until expiry or purge. Purgeable-by still applies per write (spec/commits.md §5). Check the history modes: `purge_on_replace` and keep bounds measured from "replaced" have no meaning without a value; refuse them, or define them, rather than leave them silently inert.
- **Validity** (spec/permissions.md §5.2): a validity flip (a kick) rebuilds no state for the aspect; it only changes which bodies read as valid in history.
- **Commits and sync**: storage class from the AK alone (spec/data-model.md §2, spec/commits.md §2). A durable signal part goes in durable content commits; snapshots carry none of it. Compaction never needs its bodies.
- **Undo** of a durable signal write: a purge of it, or refused. Pick one (spec/crdt.md §4.6).
- **Expiry** (spec/commits.md §6) applies per write.
- **Grammar**: `ak = ... "." version ["^"] ["~"] ["*"]` (spec/data-model.md §2). Schema rules: "a signal AK declares no expiry" holds only for `~*`.
- **API**: the write op for signals (whole-value only), `on_event`, history reads; the API's current wording that ties signals to ephemerality (notes/api.md).
- **Growth**: a notes/growth.md row: durable signal bodies are kept by design, a permanent cost per write.

## Requirements (Tess's sign-off on the wording)
spec/requirements.md says "Signals have no lasting value: they reach the nodes connected at the time, once, with no delivery guarantee, and are held by nobody." That becomes a property of ephemeral signals; durable signals get one line in user terms (entries that are kept, each authored and unchangeable by others, removable only by purge rights or expiry).

## Building it
1. Requirements wording with Tess.
2. Model: extend held-model (and roles-model if validity changes shape) with a stateless durable aspect: its bodies' fates under purge, expiry, kicks and compaction, in any arrival order.
3. Spec: data-model §2 (markers), commits §2/§5/§6, crdt §4.6 (undo), sync (signals, snapshots), permissions §5.2 where validity reads state.
4. Build: AK grammar (osis-base `Ak`, `Lifetime`), schema DSL and codegen, engine write and apply paths, snapshots skipping the aspect, history reads, the osis API.
5. Tests: small tier-1 reproducers per property (never in state; never merged; kept until purge or expiry; a kick re-judges bodies without a rebuild; ephemeral `~*` unchanged), plus the per-branch oracles for retention and validity in notes/testing.md.
6. Then move chat's messages to `chat:msgs.0*` and drop what the value forced on it (notes/chat.md).
