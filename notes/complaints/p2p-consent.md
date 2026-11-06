# p2p-consent
- First `cargo build --workspace --all-targets` at load ~30 took 706 s (a cold-ish worktree after main moved); expected a few minutes.
- The NAT model has no flow control (writes never block), so the registration window fix can only be tested in tier 2 over loopback QUIC.
- The node test harness (`tests/it/net` `disconnect`) dropped the actions of the Down it feeds a node going offline; harmless until a Down can dial (it now does, a co-reader redial), then the node held a dial nobody answered. Fixed: such dials fail at once.
- The relay tier-2 driver test hung 30 s with no log (the driver test `log()` discards); a temporary `eprintln` log was what showed the switch and the missing redial.
- At load 40-50 one `osis-node` `it` recompile took about 15 min.
