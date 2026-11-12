# A redeemer's own second node makes its link look refused
> Summary: `static_entry_refused` counts a missing static entry of K's label on any shared-set connection (`shared_static_missing`), not only the link's sharer. Bob with a second node online has a shared set with it, it lacks K, and `redeem` of a working direct link fails at once with "this link no longer works".
> Priority: normal
> Tags: node-sync, osis

Repro (sim, `no_server.rs` helpers): accounts a and b on a relay, `pair(&w, &b, 6)` placed online, `a.make_link(g, Role::Write, direct())`, `w.until(b.redeem(&link), 1000, 40)` gives `Err(Invalid("this link no longer works..."))`. With b's second node offline it redeems. The failing check is `s.static_entry_refused(&label)` in `core/osis/src/share.rs` (`join_link`, also `import_contact`); the set is filled in `shared_test` (`s.static_missing.insert`) for every connection. With no conn holding K's label and no wanted routes, `static_entry_refused` reduces to `shared_static_missing`.

Fix shape: count `static_missing` only on a connection to the link's sharer (the peer named by the link's route), or only once no other source can still hold K.
