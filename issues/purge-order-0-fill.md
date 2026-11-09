# A purge request is no longer fetched first
> Summary: `fill::a_purge_comes_with_order_0_spec_crypto_5` fails on main (ed85cdc93): a reader's first fill holds messages before the purge request, so spec/crypto.md §5 (a purge request is order 0, here before any message) does not hold. Not bisected; the signing (318bc9169..7d2394e90) and signal-edits steps 2-3 (expiring purges) merges are the candidates.
> Priority: normal
> Tags: sync, crypto

- Repro: `cargo test -p osis-node --test it fill::a_purge_comes_with_order_0`; fails the same on main's binary (`tools/bin-at main`).
- Property: a purge request reaches a node before the content it drops, so no node shows purged content while filling.
