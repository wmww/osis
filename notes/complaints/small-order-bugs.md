# small-order-bugs
- Tracing an engine state change back to its caller took a throwaway `Backtrace` print in `set_state`: at opt-level 1 most frames are inlined, so only file:line frames (filter on `/engine/src/`) told which path wrote it. A test-only `OSIS_TRACE_STATE=<ak>` hook might be worth having.
- The order harness's `alike` has no access to the held set or `played`; a tolerance that needs a delivery (here `flips`) had to be threaded in as a closure through every caller.
