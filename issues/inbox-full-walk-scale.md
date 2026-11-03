# A full pass's inbox walk grows faster than its blobs
> Summary: `inbox_certificates` over all blobs costs 15 µs a blob at 80 and 89 µs at 640 (release, loaded), much of the growth in `may_read`'s `role_of`; fine for a person, but a hostile contact's stamped blobs (up to the host's label caps) would stall a full pass.
> Tags: node-sync, scale, security

An ordinary pass skips blobs that are done (`Work::inbox_done`); a first pass on a connection, or a change of the actor's own roster or epochs, walks everything. Measured with `holders_named` cached (members-cost). Not profiled past section timers: of 640 blobs' 120 ms, about 47 ms in `inbox_about`, 37 ms per `may_read` call site. `vet_inbox_hints` still walks every blob, at 0.25-0.5 ms per 640. Tied to the owner's call on what bounds a connected sender.
