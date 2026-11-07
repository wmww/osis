# Rename the "person actor" to "account"
> Summary: the engine still calls the account actor (its nodes and its recovery key are its admins) the "person actor" (`create_person`, `set_person`); the name misleads, as nothing ties it 1:1 to a human (Tess). Everything public says account.
> Priority: low
> Tags: spec, api, naming

Tess's direction. Pre-stability; no wire change. The API, CLI, app, chat, notes and spec prose are done. Left: engine and node names (`create_person`, `set_person`, `flows`, `c.person`, the `person` local record).
