# gimbal-slim-survey
> Summary: Footguns met while measuring per-unit overhead.

- The `thing_cost` tests report the opened commit (`Engine::package`) as "downloaded" and count no sync store rows or sealed blob: half the real cost of a small commit was invisible. A sync-harness world (`net.between`, `disk_use`, store `scan_local`) gives the wire and both stores; `OSIS_SYNC_TRACE=all` names every frame.
- Calling `Engine::seal_package` in an engine test writes a `dw/` row at the maker: a measurement that seals changes the census.
