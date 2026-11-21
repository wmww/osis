# driver-follow
- No per-step round or follow counter outside the harness's `ROUND_CAP` check: measuring rounds across the osis-sync suite took a throwaway env-var logger in the driver. Its first version used `writeln!` to a shared append file, which splits into several writes and interleaved lines between test threads (bogus 4111-round steps); one `write_all` per line fixed it.
