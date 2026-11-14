# Node-sync checks an entry's upload stamp several times per node
> Summary: A commit's signature is checked once per node (notes/engine.md, Signature verdicts), but node-sync verifies the upload stamp of each synced entry about three times per write across the nodes (plus the host's one at upload), at about 0.43 M instructions each: the same (key, digest, signature) checked again where a verdict kept with the entry would answer.
> Priority: normal
> Tags: sync, performance

Counted with `Domain::verify_cost` counters, a writer and a reader through a host (`hosted::<2, 1>`), one register write per step, at 5 and 50 writes (per write, flat): stamp 4.3 (`proto::session` upload check at the host 1.1, `sync/inbound.rs` `signed_by` 2.2, `sync/pass/mod.rs` the `stamped` check 1.0), delete 1.0 (the host's check of each delete request: distinct requests, not repeats), commit 1.0 (the reader's one), possession 0.16.

Left for the sync rewrite (coordinator Capstan; node-sync, host and proto session code were frozen when commit signatures were fixed): an entry's stamp is a function of its bytes and the head's write key, so its verdict belongs with the entry where it enters (as `Signed` is kept with a commit), keyed by exactly what verified (the key included: a head key resolved otherwise later is checked anew). A re-check that guards a different input says so.
