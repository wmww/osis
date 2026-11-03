# Each home-label pass walks every inbox blob
> Summary: `inbox_certificates` walks all unexpired blobs each pass, at 15 µs a blob at 80 and 89 µs at 640 (release, loaded), much of the growth in `may_read`'s `role_of`; fine for a person, but a hostile contact's stamped blobs (up to the host's label caps) would stall every pass of the home label.
> Tags: node-sync, scale, security

Of 640 blobs' 120 ms (section timers, not profiled), about 47 ms in `inbox_about`, 37 ms per `may_read` call site. `vet_inbox_hints` also walks every blob, at 0.25-0.5 ms per 640. A done-set with wake triggers (`Work::inbox_done`, removed in review, in git history) cut an ordinary pass to 0.1 ms, but not a full one. Look here first if the owner wants a bound on a connected sender; making the per-blob cost flat in things held may be enough.
