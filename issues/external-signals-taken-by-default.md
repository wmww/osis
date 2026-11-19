# Every independent thing takes every external signal and any grant
> Summary: Decided by Tess; specified and modelled, not built: a party holding no write fires an external signal validly only while the thing's current setting enables it (spec/permissions.md §5.2 External fires; held-model `ExternalFires::Enabled`). The engine still takes every `@~` fire from anyone; externally grantable and KEM keys following it are stage A5.
> Priority: normal
> Tags: security, perm, sync, spec

## Decided (Tess)
- **External signals: off unless named.** A fire of an external signal the thing's admin-only setting does not name is invalid, not merely unkept. The retention entry that keeps a signal's fires is the switch, per signal.
- **Ordinary signals: no switch.** A writer may write any aspect of a thing, so a switch on signals alone would follow from no rule of the data model.
- **Being granted roles by a non-admin is an unusual property a thing's admins turn on**, one switch with taking tickets; keys follow the switch; without it, write on a thing gives the right to grant to it, a reader may not. Designed: notes/write-path-design.md §4 (externally grantable, what enabling publishes, the granter's node refused) and §3 (the card).

## Done
The rule in the spec (spec/permissions.md §5.2 External fires, spec/commits.md §5 The setting and In force, spec/sync-inbox.md §1-§2 and §4, spec/data-model.md §2) and in held-model (`Held::external_fires`, properties in `core/test/held-model/tests/it/props_external.rs`, rule tests in `spec_signals::external`). The setting deciding is the current one, not the one in force at the fire's key: notes/write-path-design.md §4 External fires says why.

## To do
- **Engine and perm** (redesign stage S2, brief 3): judge a fire valid by its author's authority, else iff the current setting enables its signal (`apply::validity`); judge fires again when the current setting changes; promotion follows validity (`Engine::promotable`); a reader writes no unenabled fire. Then flip osis-engine `tests/it/held.rs` to `external_fires: hm::ExternalFires::Enabled` so `order::held_set_decides` compares against the rule, and add the engine rule test (an unenabled fire reaches no listener and is not promoted).
- **`osis` enable call** (notes/api-design.md) and **CLI**; name a refusal by the setting, never by keys.
- **First-party schema and app** (brief 4): which kinds of thing enable which signal by default. A thing that is its own inbox (every synced thing but an account, spec/data-model.md §9) takes tickets, removal notices and stranded notices from parties holding no write only once enabled: until then a removed holder that is such a thing learns of its removal only from its own writers' timeline, and a stranded reader with no writer connected gets no re-seal by notice (a stranded writer's fire stands by its authority).
- Stage A5: externally grantable as what a thing publishes, cards, KEM keys following the switch; spec/requirements.md Permissions brought to the rule once roles-model has checked grants from outside (notes/write-path-design.md §6).
