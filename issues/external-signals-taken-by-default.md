# External signals off unless enabled: grants from outside
> Summary: Built: a party holding no write fires an external signal validly only while the thing's current setting enables it (spec/permissions.md §5.2 External fires); core enables none by default. Left: externally grantable with KEM keys following the switch (stage A5), and the account library enabling its inbox's signals (accounts piece 2).
> Priority: normal
> Tags: security, perm, sync, spec

## Decided (Tess)
- **External signals: off unless named.** A fire of an external signal the thing's admin-only setting does not name is invalid, not merely unkept. The retention entry that keeps a signal's fires is the switch, per signal.
- **Ordinary signals: no switch.** A writer may write any aspect of a thing, so a switch on signals alone would follow from no rule of the data model.
- **Being granted roles by a non-admin is an unusual property a thing's admins turn on**, one switch with being offered grants from outside (`grant@~0`); keys follow the switch; without it, write on a thing gives the right to grant to it, a reader may not. Designed: notes/write-path-design.md §4 (externally grantable, what enabling publishes, the granter's node refused) and §3 (the card).
- **Core has no default (Tess).** A thing takes no grant from outside until its admins enable it, whatever kind of thing it is. Which things enable it is the apps' and libraries' choice: an account's inbox does, nothing else by default (kit and chat enable none on what they make).

## State
`osis::core::RetentionSetting::enable_inbox_signals` adds `grant@~0` and `stranded@~0` (`osis_schema::core_types::INBOX_SIGNALS`), each kept `INBOX_LIFETIME`. No code path calls it at creation until the account library makes an account's inbox (notes/accounts-switch-brief.md piece 2). `osis enable T AK` requires `--keep DUR`: an entry with no history enables a signal but keeps no fire, so no node could fire it. Not to build: core turning signals on when a thing is first shared (it would change behaviour at sharing and bring back signals its admins turned off).

## To do
- Stage A5: externally grantable as what a thing publishes, cards, KEM keys following the switch; spec/requirements.md Permissions brought to the rule once roles-model has checked grants from outside (notes/write-path-design.md §6).
- Engine against the model: issues/held-set-external-fires.md.
