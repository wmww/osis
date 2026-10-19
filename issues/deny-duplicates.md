# `cargo deny check` fails on main
> Summary: Since the osis-crypto merge, bans fail on duplicate versions (chacha20, cpufeatures, getrandom, hax-lib*, rand_core, shlex, syn) and advisories on unmaintained proc-macro-error2; deny.toml has no `skip` entries yet.
> Tags: tests, crypto

Most duplicates come through libcrux-ml-kem (hax-lib 0.3/0.4, libcrux-traits' rand 0.10 / rand_core 0.10) and dev or build deps (proptest's chacha20 0.10, blake3's cc → shlex 2, cpufeatures 0.3), several only on other targets. Fix: a `skip` per unavoidable duplicate with its reason (deny.toml says so), an `ignore` with reason for the proc-macro-error2 advisory if it is a build-only proc macro, or newer upstream versions. Check with `cargo deny check`.
