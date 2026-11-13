# no-merger
- `schema/core.osis` defines the `box` enum separately from `core_types::SecretBox`: adding a Rust variant compiled everywhere and every rotation then failed at commit verify with "a value the core type does not take". A test tying the codec enum to the schema type would catch it at build time.
- `run.sh depth0` takes 15+ min at one worker on a loaded box (D0_gone_live alone 472 s), past the "under 3 min per module" its header states.
- A first TLC liveness run hung for minutes with no progress lines through `grep`: TLC prints progress once a minute, so filter the log after the run, not live.
