# 2b-regress
- The sim's sync trace (`OSIS_SIM_TRACE`) truncates long messages, so an Upload's later blob IDs never show; finding where a node marked a blob present took a backtrace probe in `State::set_present`.
- `with_arrivals` (the work-sets oracle's compared mode) changes the run's dice (`compared()`), so a single `replay` without it never reproduces a parted work-sets seed; wrap the probe in `with_arrivals` too.
- Tier 1 took 506 s wall on a loaded box (notes say about 150 s quiet).
- Review: an `eprintln` probe in a passing sim test shows nothing without `--nocapture`; gate took 420 s on a loaded box (notes say about 4 min).
