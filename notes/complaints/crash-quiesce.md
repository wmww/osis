# crash-quiesce
> Summary: workflow notes from the host-crash quiescence fix.

- The "one more round changes" list in a not-quiescent failure is churn since quiescence began (`heads0`), not one round's: it read as a place/delete loop when the run was a stall. The round lines' constant fingerprint plus `requests stalled` diagnostics were the real signal.
- Finding the write path of a planned crash took a throwaway backtrace in `Faults::check`; a sim trace line naming the device and call at a planned crash would save that.
