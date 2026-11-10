# host-set
- At load 25-35 a core build after a branch switch took 12.6 min and a GUI build 11 min: confirming a build-profile cause on the real tree costs an hour of waiting. A 3-crate scratch workspace (`--offline`, proc-macro2 + unicode-ident) reproduced it in seconds and tested fixes; start there for any cargo-behaviour question.
- The fingerprint's `profile` hash includes cargo's per-unit LTO decision, which neither `--unit-graph` nor `cargo tree` prints; only the `-v` rustc lines show it (`-C lto=off` or not).
