# External signals off unless enabled: first-party enabling and grants from outside
> Summary: Decided by Tess; specified, modelled and built in engine, perm, `osis` and the CLI: a party holding no write fires an external signal validly only while the thing's current setting enables it (spec/permissions.md §5.2 External fires). Left: first-party schema and app enabling what they need (brief 4), and externally grantable with KEM keys following it (stage A5).
> Priority: normal
> Tags: security, perm, sync, spec

## Decided (Tess)
- **External signals: off unless named.** A fire of an external signal the thing's admin-only setting does not name is invalid, not merely unkept. The retention entry that keeps a signal's fires is the switch, per signal.
- **Ordinary signals: no switch.** A writer may write any aspect of a thing, so a switch on signals alone would follow from no rule of the data model.
- **Being granted roles by a non-admin is an unusual property a thing's admins turn on**, one switch with taking tickets; keys follow the switch; without it, write on a thing gives the right to grant to it, a reader may not. Designed: notes/write-path-design.md §4 (externally grantable, what enabling publishes, the granter's node refused) and §3 (the card).

## Done
- Spec (spec/permissions.md §5.2 External fires, spec/commits.md §5 The setting and In force, spec/sync-inbox.md §1-§2 and §4, spec/data-model.md §2) and held-model (`Held::external_fires`, `props_external.rs`, `spec_signals::external`). The setting deciding is the current one, not the one in force at the fire's key: notes/write-path-design.md §4 External fires says why.
- Engine and perm: `apply::validity` `Judge::part` (a fire valid by its author's authority, else iff `setting_now` enables it); `validity::setting_moved` re-judges a thing's external fires whenever its held settings move (held, dropped, purged, flipped); promotion, a sealed fire's ticket, removal notice and stranded notice, and `take_fire` all follow the fire's validity. A reader's own fire of an unenabled signal is refused (`Error::NotEnabled`, wire code 16); a sealed fire's sender is bound by no setting. osis-engine `tests/it/held.rs` runs `ExternalFires::Enabled`; rule tests in `tests/it/external.rs`.
- `osis`: enabling is an entry in `core::RetentionSetting::rules`, written with the whole setting (no separate call: the entry is also what keeps the fires); `Error::NotEnabled { tid, signal }`. CLI: `osis enable T AK [--keep DUR]`, `osis disable T AK`.

## To do
- **First-party schema and app** (brief 4): which kinds of thing enable which signal by default. Every thing but an account's inbox is default-off. A thing that is its own inbox (every synced thing but an account, spec/data-model.md §9) takes tickets, removal notices and stranded notices from parties holding no write only once enabled: until then a removed holder that is such a thing learns of its removal only from its own writers' timeline, and a stranded reader with no writer connected gets no re-seal by notice (a stranded writer's fire stands by its authority). Places that need a decision:
  - `stranded@~0` on every shared thing with readers: chats (`libs/chat` `create`), kit and app things (`osis_kit::store`, the demo data); engine test `rotation::tests_stranded::a_writer_taking_a_stranded_notice_reseals_its_holder_spec_sync_inbox_5` enables it in its setup.
  - `ticket@~0` and `removal@~0` on things granted a role on other things (realms, tag-like holder things), once something first-party grants to a thing holder.
- **Engine against the model**: osis-engine `tests/it/held.rs` passes `ExternalFires::Enabled`, but `order::held_set_decides*` generates no external fire (held-model's external worlds, `held_model::external`, run against the model alone): run those worlds through the engine adapter so the comparison reaches the rule.
- Stage A5: externally grantable as what a thing publishes, cards, KEM keys following the switch; spec/requirements.md Permissions brought to the rule once roles-model has checked grants from outside (notes/write-path-design.md §6).
