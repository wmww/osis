# sim-shared-setup
- Each by-hand sweep measurement (before, after) waited 13+ min for the heavy lock behind other branches' gates, longer than the 2-3 min run itself.
- `copying::cached` returns the type it keeps (`copy: FnOnce(&mut W) -> W`): a cache of `Result<world>` must hand back a `Result` and the caller unpack, a surprise on first use.
