# cert-bodies
- Read's internals (an `Effects` key's last value, whether it is followed) are unreachable from a World test: finding that a key held `{Log}` while nothing was logged took temporary `pub` probes in osis-base, the driver and read. A test-only dump of read's judgements per (S, commit) would have saved most of the hunt.
- Bug class: an act that can fail (`log_own` returning `None`) behind an `Effects` value that does not change when it later could succeed. Any act whose success depends on state the judgement does not read has the same shape.
- A probe's `eprintln!` in a passing test is swallowed: an A/B comparison "found nothing" until rerun with `--nocapture`.
- Logging bodies earlier changed seed 7's timeline and exposed a latent store bug (own entries never parked, so a node's own logs of commits forgotten with lost access never opened again); a 100-seed run before and after was what told a regression from a newly reached path.
