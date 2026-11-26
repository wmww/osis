# What a commit pays per enclosing unit
> Summary: A small commit on an independent thing carried under one enclosing unit cost about 1230 B more on the wire per reader pair, one sign and two stamp verifications more than the same commit on the root (counted once, on an earlier sync build: count again first); the entry it adds under the enclosing sync ID accounts for well under half. Find the rest and cut what the built unit does not need.
> Priority: normal
> Tags: sync, engine, performance

Inherent per enclosing unit (notes/sync-unit-scope.md): the entry (blob ID 32 B, wrap 57 B, stamp 64 B, about 153 B, spec/wire.md §5), its frame, the stamp's sign and its check at each receiver (notes/thing-cost.md, Survey).

Candidates for the rest, to rule in or out by counting the frames of the two commits side by side: a per-sync-ID copy of the body (spec/sync-judgement.md §1 Per-sync-ID copies: a second encryption where the enclosing unit's readers cannot open every section, about 1 KB for a small commit), certificate copies logged under the enclosing sync ID, the reader's echo of the entry (notes/slim-design.md C). Count at n and 10n enclosing units in a default test (notes/priorities.md, Slimmer things).

Seen since (notes/slim-design.md G): an independent thing made in A's unit sends its rotation twice to A's second node, a 4,046 B per-sync-ID copy under A's sync ID beside its 4,174 B blob under its own, and its content commit (752 B) inline under both; candidates C and G there.
