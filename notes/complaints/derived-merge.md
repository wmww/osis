# derived-merge
- A node test whose new rule made a rotation loop ran 10+ min silently: `cargo test ... | tail` shows nothing until exit, and `Net::settle`'s round guard never fired (the loop was inside each step's pass-end rotations). Run new node tests with `--nocapture` to a log first.
- No gdb/perf on the box: a hung test can only be diagnosed by rebuilding with prints (each rebuild 1-5 min at load 20).
- `run.sh depth0` at one worker took 23 min (D0_nc3 514 s, D0_gone_live 409 s), well over the "under 3 min per module" its header says.
