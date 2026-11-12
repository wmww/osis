# churn-413
- `OSIS_SYNC_TRACE` prints only node-side wire messages, not which rule placed or deleted an entry or which node's tid it is; finding the two disagreeing rules needed temporary eprintlns in `body_sends`/`encrypt_again`/`deletions`/`carried`. A trace line per placement and per delete with the node's tid and the verdict (why, live, carried by) would make a loop readable in one run.
