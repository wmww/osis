# Sourced by tools/icount and tools/cpuprof: exports each `.cargo/config.toml` [env] value not
# already set, as cargo does, so a test binary run outside cargo runs what `cargo test` runs
# (PROPTEST_CASES=32, no failure persistence) instead of proptest's 256 cases.
eval "$(awk -F' *= *' '/^\[/ { e = ($0 == "[env]") } e && /^[A-Z_]+ *=/ { gsub(/"/, "", $2); printf ": \"${%s:=%s}\"; export %s\n", $1, $2, $1 }' "$(dirname "$0")/../.cargo/config.toml")"
