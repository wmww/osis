# durable-page-cap
- `scale::big_map_apply_memory` at 10^6 needs about 14 GB: run alone. Per-step peaks from `VmHWM` with `clear_refs` are lower bounds after the first step, because glibc keeps freed memory (`GLIBC_TUNABLES` trim settings did not change that); there is no allocator stat without unsafe code.
- The issue's "honest pages stay under about 3 x 2^18 bytes" was wrong: text runs with dense position and flag writes, and many-member `Slots`, go past it. Check worst cases by measurement, not only from the paging rules.
