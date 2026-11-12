# A full capped peer keeps an ephemeral entry no node holds
> Summary: `ephemeral::random_window_one_capped_host_large` seed 1811714465 (on main too): the only peer that cannot read the label is full and keeps an ephemeral entry that every holder dropped, so its deletion never came and the stale entry takes room a held entry needs.
> Priority: normal
> Tags: ephemeral, sync, tests

- Repro: `OSIS_EPH_START=1811714465 OSIS_EPH_SEEDS=1 cargo test -p osis-node --test it -- --ignored --exact ephemeral::random_window_one_capped_host_large` (fails on main at b5cfd7f8c and on net-3i alike).
- Failure: "the full host keeps entries [BlobId(d8f25c5e..)] no node holds (cap 4000)". Not traced: which holder dropped the entry without deleting it at the peer (absorbed under a snapshot, expired, forgotten) and why no right holder deleted it there.
