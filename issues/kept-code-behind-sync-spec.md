# Kept code behind the new sync spec
> Summary: Code that Phase 3 keeps still implements rules the new sync spec replaced: the LAN announcement, an actor with no inbox, and `label.0` peer lists.
> Priority: normal
> Tags: transport, crypto, osis, spec

Found while repointing citations after the sync spec split (issues/sync-rewrite.md). Each site cites the new section, whose rule now differs:
- **LAN announcement**: spec/sync-transport.md §4 is `"osis lan 2"`, 44 bytes, no tag, lan secret or sealed signature. Still the old design: core/transport/src/lan.rs, core/crypto/src/keys.rs (lan secret, tag), core/crypto/src/kdf.rs, core/crypto/src/sign.rs, core/test/vectors/src/subjects/lan.rs and keys.rs, core/test/vectors/README.md.
- **No inbox named**: core/osis/tests/it/tied.rs ("an actor naming no inbox uses its first admin's") against spec/sync-inbox.md §1 (a sender with no inbox named cannot reach the actor).
- **`label.0` peers**: core/osis/tests/it/sync.rs and core/osis/src/share.rs read a peers/hosts list in `label.0`; `sync.0` (spec/sync-ids.md §4) holds steps only. Likely goes with Phase 3's rename and rebuild.
