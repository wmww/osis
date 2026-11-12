# uncover-held-cover
- The brief's suggested fix (ask whether a held snapshot covers the dropped body now) cannot work: with the body gone, `covered` says covered for almost any held snapshot, and frontier tables never reach expiring deltas or dead writes. Took a while to see that the recorded chain is the only evidence; the fix keeps it whole across forgetting instead.
- The scratchpad task directory must exist before redirecting a background command into it; the first engine test run died on that and still reported exit 0 to the notification.
