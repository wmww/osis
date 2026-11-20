# root-tables
- `LocalPeer::cached` worlds are built under whatever `PageParams::set_test` was active at first build; a test copying one under other params reads the world's own paged states by the wrong rule (now refused). Cache a world per params (key includes them).
- `world` drop runs end-of-history checks: a test that restores `set_test` before its worlds drop reads them under FORMAT params. Drop worlds first.
- Durable commits waiting on pages are examined (signature + decode) at every blob stored (issues/blob-wait-examined-per-wake.md): made a "does the walk's refusal matter" probe confusing, since the per-round decode refused the chain by itself.
