# net-test-aliases
- The "tier 1 never binds the real LAN" claim was wrong: in-process CLI tests of `watch`, `--follow` and `--watch` forms bound 47380 and broadcast. An abort in `Lan::bind` did not show it; `strace -f --seccomp-bpf -e trace=bind,sendto` did, cheaply.
