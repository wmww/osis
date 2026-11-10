# A GUI build compiles a second set of core build-time units
> Summary: After `cargo build --workspace --all-targets`, `cargo build --all-targets` (core alone) compiles osis, osis-perm, osis-schema, osis-vectors, osis-cli, osis-sim and osis-bench again: the host (build-script) chain under osis-schema differs between a core build and any build naming osis-kit/osis-app, down to `unicode-ident`'s host profile fingerprint. The gate's unification check fails on every gate that touches a manifest, in a worktree that has not built both sets yet.
> Priority: normal
> Tags: build, tests

Found by the gate-review gate (stack of epochs-side and gate-shape, which change no profile or dependency): `unification_check` reported `the default members alone compiles: osis-bench osis osis-cli osis-sim osis-perm osis-vectors osis-schema`. The last passing unification check known is gate-shape's own gate, on 17f4e9b01; main since added `lto = "off"` to `[profile.dev]` (002a771dd), the prime suspect, not confirmed.

What differs (fingerprints in `target/debug/.fingerprint`): the build-dependency osis-schema is `libosis_schema-e49e8b86e54c2915` in `cargo build --all-targets` and `-2ef6f6fb5da1d5f8` in `-p osis-kit -p osis-app` or `--workspace`. Its host osis-base differs through blake3, zeroize and tracing, each through zeroize_derive / tracing-attributes, syn, quote, proc-macro2, ending at `unicode-ident`, whose two host units differ only in the fingerprint's `profile` hash. Features are identical (`cargo tree --target all` diff, and nightly `--unit-graph` shows the same units, profiles and features in both builds), so the difference is in a per-unit setting cargo computes and the unit graph does not print (an LTO or embed-bitcode decision is the likely one).

The check passes once both sets exist (every unit fresh), so a warm worktree that built the GUI before hides it.

Next: build core then GUI in a scratch target with `lto = "off"` removed to confirm or rule out the LTO setting; if confirmed, the fix is Tess's (she chose lto off): accept the second host set and say so in notes/build.md Feature unification, or find a setting that keeps both.
