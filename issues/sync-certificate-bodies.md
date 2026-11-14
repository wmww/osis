# Certificate blobs are not in the engine's required set
> Summary: `Engine::sync_bodies` lists closure bodies only, so read judges every certificate entry under S (another node's card, chain certificates, record and list blobs, revokes, grant copies) outside the required set: must-not-hold, dropped from the own store and deleted at store sources by a delete-key holder.
> Priority: critical
> Tags: sync, engine

spec/sync-judgement.md §2 puts the certificate blobs of spec/permissions.md §4 in S's required set. `sync_bodies` (core/engine/src/sync/bodies.rs) never emits a `BodyMeta` with `certificate: true`; read (`judge::body`) then finds no body of the commit under S and, once the closure is settled, judges it `MustNot(OutsideRequired)`. Seen while building the card rules (`card_superseded`, `card_ended`): a node's `reach.0` card has no body under D's home, so those rules are judged by header in `read_facts` but read never asks for them.

Needs: certificate bodies per sync ID in `sync_bodies` (the card under D's home; each chain's parts as copies where the closure's bodies do not carry them), and `seal_body` for a certificate copy (through `Engine::seal`, the reseal contract). Until then every module that judges entries under S over-deletes certificates.
