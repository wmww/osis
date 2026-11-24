# External signals off unless enabled: grants from outside
> Summary: Built: a party holding no write fires an external signal validly only while the thing's current setting enables it (spec/permissions.md §5.2 External fires); first-party things enable their inbox signals at creation. Left: externally grantable with KEM keys following it (stage A5).
> Priority: normal
> Tags: security, perm, sync, spec

## Decided (Tess)
- **External signals: off unless named.** A fire of an external signal the thing's admin-only setting does not name is invalid, not merely unkept. The retention entry that keeps a signal's fires is the switch, per signal.
- **Ordinary signals: no switch.** A writer may write any aspect of a thing, so a switch on signals alone would follow from no rule of the data model.
- **Being granted roles by a non-admin is an unusual property a thing's admins turn on**, one switch with being offered grants from outside (`grant@~0`); keys follow the switch; without it, write on a thing gives the right to grant to it, a reader may not. Designed: notes/write-path-design.md §4 (externally grantable, what enabling publishes, the granter's node refused) and §3 (the card).

## Where enabling is decided
- First-party code enables at creation: `osis::core::RetentionSetting::enable_inbox_signals` adds `grant@~0` and `stranded@~0` (`osis_schema::core_types::INBOX_SIGNALS`), each kept `INBOX_LIFETIME` as an account's inbox (`RetentionSetting::take_inbox_signals`, which the account's creation uses too). Chat's `create` and kit's `start_setting` (kit things, app homes, demo data) call it. A plain `osis create` and engine-made things enable nothing.
- `osis enable T AK` requires `--keep DUR`: an entry with no history enables a signal but keeps no fire, so no node reading the thing could fire it (a fire is history); that entry is still writable as a setting.
- Libraries turn them on at creation (Tess): the setting stays the app's own choice. An app writing its own setting without `enable_inbox_signals` gets sharing where a grant from outside reaches its holder's nodes by no offer and a stranded reader stays stranded, with no error.
- Not built: core turning them on when a thing is first shared. It would change the setting at sharing (against "sharing a thing never changes how it behaves") and bring back signals its admins turned off; it can be added later (one write at `rotation::own_secrets_rot`, no format change).

## To do
- Stage A5: externally grantable as what a thing publishes, cards, KEM keys following the switch; spec/requirements.md Permissions brought to the rule once roles-model has checked grants from outside (notes/write-path-design.md §6).
- Engine against the model: issues/held-set-external-fires.md.
