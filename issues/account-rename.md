# Rename the "person" leftovers to "account"
> Summary: the account actor is "account" everywhere public and in the engine's API; "person" for it remains in test helpers (`persons`, `person` in node, keys and sim tests, sim `NetSim::person` scenarios), osis `share.rs` `person_links`, node-sync `set_contact(person, ..)` and a few engine and node comments. Rename them; nothing ties an account 1:1 to a human (Tess).
> Priority: low
> Tags: naming, tests

The app's **Person** kind (an address-book contact) is another sense and stays (issues/deprecated-terms.md).
