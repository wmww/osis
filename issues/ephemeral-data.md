# Ephemeral data: one state system for an app
> Summary: The owner wants apps to be able to hold state that is neither persisted nor synced (UI state, scratch models) through the same `osis` API as durable data, and to switch a thing between the two cheaply, so one state system serves everything. Today "not synced" already falls out of placement (a thing in no labeled group is not synced, spec/sync.md §5), the store has an in-memory backend only for whole test databases (`MemStore`), and nothing makes a single thing volatile. Design belongs to the API pass; no wire impact unless a volatile thing can be placed in a synced group.
> Tags: api, node, sync

What exists: `Place::In(group)` decides sync; a thing in no labeled group is local and durable. `MemStore` (core/osis) backs a whole database in memory (tests). Synthetic local aspects (`/tid`, `/aspects`, `/groups`) are computed, never stored.

Questions for the API pass:
- Unit of volatility: per thing (simplest: a creation option `Volatile`, kept in the node's memory tables, never written to the store), per aspect (a schema flag like `synthetic`, so one thing mixes durable and scratch fields), or per owner (everything under a volatile actor is volatile).
- Switching: a volatile thing becoming durable must keep its tid (the owner called changing ownership a known wart; a tier change must not be a move), so volatility is a node-local property of the thing, not part of its identity or creation record. Durable → volatile is a local forget plus re-create in memory, or just a flag flip with the stored bytes dropped.
- What must work alike: typed reads and writes, watches, path ops, undo (history for volatile things lives in memory and dies with the process), queries/backlinks once they exist, group placement of volatile things with durable ones (`/group` on a durable group naming a volatile thing: never synced, since the thing has no label; readers on other nodes never see it).
- Bounds: memory use of volatile state is the app's; the node needs no budgets beyond what it has for in-memory caches.
- Simplest candidate under the owner's lens: a per-thing `volatile` flag recorded at creation (local), honoured by the store layer (writes go to an in-memory `Store` backend keyed like the durable one) and by sync (a volatile thing is never placed under a label, whatever groups name it); switching tiers copies the thing's aspects between the two backends under the same tid.

## Owner direction (round 13)
- Name: ephemeral (cheap, disposable; no hard guarantee it never touches disk). Vision: all of an app's state lives in osis; the UI drives and is driven by it.
- Ephemeral is an axis independent of sync: local by default, synced by group placement as usual. Four cells: durable local, durable synced (exist), ephemeral local (scratch UI state), ephemeral synced (cursors, presence, typing).
- Likely unit: per aspect, declared in the schema (a durable doc's `/cursor` ephemeral for every app); per thing later if needed. Switching keeps the tid.
- Cost target: local ephemeral writes only slightly heavier than an in-memory structure: no signing, hashing, encryption or store journaling; typed reads, writes, watches, merge, undo (in memory) alike. Synced ephemeral writes are signed.
- Synced ephemeral state: servers and peers keep the latest value per (writer, aspect) under a label in memory, bounded by per-label caps, handed over on subscribe, so late joiners get it on sync; lost on restart, writers re-send on reconnect; presence-like values carry a short expiry.
- Signals: none of their design is fixed; fold them into ephemeral data wherever it fits (possibly a signal is an ephemeral write with no lasting value), fewest distinct concepts.
- Order: design write-up first (API, schema, wire, server memory), then build; after the commit-query API work.
