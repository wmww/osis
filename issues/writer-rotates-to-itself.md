# A hostile writer can lock everyone out of an actor by rotating to itself
> Summary: any writer may rotate read and write and seal the new secrets only to itself; every other node then holds no current secret, refuses any rotation and so any removal (spec/crypto.md §4, `flows/edges.rs`), and only the vandal can re-seal. No recovery today short of a new actor. Found by reading in the chat design; not run.
> Tags: security, permissions, keys, engine

Applies to any shared actor with writers. Members of a chat must hold write to stamp uploads, so every member can do it. issues/fork-held-by-non-rotators.md covers only the honest shape.

Possible recovery (unverified end to end): an admin writes the removal with a frontier omitting the hostile rotation's commit ID. Role commits are commit form, so they are listed only by ID, and spec/permissions.md §5.2 then invalidates that rotation everywhere; its epoch is not established and the previous epoch is current again, which the admin holds and rotates from in the same commit. Receivers already judge this; only the writer-side refusal blocks it. Needs an admin: a hostile sole admin or an admin-less actor has no recovery.

Frontier study (notes/frontier-study.md): the recovery stays possible under the recommended §5.1 rule only because it sanctions a deliberate omission (a received, undroppable commit left out as an admin's repudiation); "always list role commits" (item 219 carry-over) would block it. The writer-side flow fix (judge under the new frontier before choosing epochs to rotate from) is step F3 there.
