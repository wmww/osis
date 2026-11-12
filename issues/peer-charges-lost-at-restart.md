# Peer budget charges are lost at a restart
> Summary: `Charges` (the peer budgets, `charge_reader`, `charge_deposit`) live only in memory, while the label entries they bound are durable; after a restart a peer's entries that give nothing held stay stored uncharged and it can fill its budget again, once per restart.
> Priority: normal
> Tags: security, node-sync

- What: notes/peers.md Budget; `Charges` in core/node/src/sync/serve.rs keeps `by_entry`, `per` and `total` in memory only. Entries (`State::entries`) and what they carry (pending rows, a header kept for a part dropped as invalid) survive a restart. Entries at a host are bounded by `unvouched_cap` instead, so the gap is entries from co-reader peers and deposits, at no host.
- Effect: a peer that streams `peer_bytes` of entries giving nothing (`gives_nothing`), waits for a restart and streams again keeps adding them: storage grows by a budget per restart (spec/requirements.md: peer input never grows storage unbounded). Each such entry still goes once it is judged or its carrier leaves, so only entries that stay giving nothing pile up.
- Fix sketch: store the charge key (`charge_key`) and the size as it came with each entry row, and rebuild `Charges` at open from the entries that give nothing and are present at no host (`prune_charges`' own test), so the budgets read the same after a restart. Test: stream a budget of a reader's invalid commits, restart, stream more; the second batch is refused and the store at 2 restarts is the store at 1.
