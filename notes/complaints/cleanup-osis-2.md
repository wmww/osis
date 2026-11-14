# cleanup-osis-2
- dup_windows.py found little in core/osis (largest 6 lines); the volume was in an infallible `Result` (`status_of`) that kept a dead error path and a `Locked` flag alive. A probe for `Result`-returning fns whose bodies never return `Err` would have found it first.
- The `pub(crate)` probe flags types used only in their file, but a type in a `pub(crate)` field (`Life`, `Stop`) must stay `pub(crate)`: rustc's private-interfaces error tells.
