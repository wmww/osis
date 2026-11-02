# Purge rights should not be a nested scale
> Summary: `Purgeable by` is the ordered scale `nobody` < `admin` < `author` < `writer`, so a right for the author always includes admins. Owner: both "admin can delete, author can't" and "author can delete, admin can't" must be supported, generally, not just for chat. The first exists (`admin`, unless the author is also an admin); "author but not admins" does not.
> Tags: spec, permissions, engine, crypto, commit

Owner direction: consider other modes this implies. Writers include admins and the author by definition, so the distinct useful sets look like: nobody; admins; author; author + admins (today's `author`); all writers. Replace the scale with those named cases or a set; a pre-stability format change is fine.

Touches: wire class (spec/wire.md §2 and aspect `Retention`), spec/commits.md §5 and spec/permissions.md §8, delete levels (spec/crypto.md §7: today level 1 is `admin` and above, level 2 `author` and above, so an author-only delta must commit to level 2 with no level 1), `core/perm/src/purge.rs`, two `PurgeBy` enums (perm, schema), `commit/validate`, node `local.rs` and engine `apply/free.rs`, schema syntax, compaction and `covered` where rights decide a drop (an author-only body: who may compact it?), vectors.

Check what an author-only delta means when: the author has left or been removed (nobody can purge it: a body with no recourse short of removing access, and is that acceptable?), an imported delta (level 2 omitted today), admins compacting, `keep at most` relative (only under `writer` today), an admin who is also the author, a thin client's actor. Design chat E (notes/chat-designs/e.md) lists "admins cannot delete" as incompatible; this moves it to a setting.
