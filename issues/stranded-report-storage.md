# A stranded notice makes its receiver store what a depositor chose
> Summary: a stranded notice is taken without the inbox's admission check (no sender to check), so anyone holding an admin's deposit seed who knows a label it syncs and a current holder of the label's actor (the admin's own account will do) makes the admin apply and keep any valid `roles.0` commits and creation records it carries, unbounded over notices. Only the named holder's keysets are taken, so no keyset is planted; the cost is storage.
> Priority: normal
> Tags: security, node-sync

## Shape
`SyncEngine::stranded_report` takes a report's holder keys (`take_holder_keys`) once the named holder is a current holder of the actor and the receiver may re-seal it. `keys.0` parts are cut to the holder and its writers' cards; `roles.0` parts and records are not cut, as an honest report's chain (`chain_under` per current `keys.0` commit) runs through actors the receiver cannot list in advance. An admitted inbox payload's chain has the same reach, but admission (`admits`) asks for an author with a current role; a notice has no author. The notice blob leaves under the inbox caps (`clear_inbox`); what it carried stays.

## Options
- Demand-driven taking: ingest the holder's `keys.0` commits first and take a chain commit or record only as one of them awaits it (`Ingested::Awaits`, pending reasons). Bounds a notice to the holder's own history.
- Take a notice's keys only once the re-seal pass finds the holder left out for want of a keyset (`Sealed::Out`): an admin that seals the holder fine takes nothing.
- Stated limit: storage only, bounded per notice by the blob size.
