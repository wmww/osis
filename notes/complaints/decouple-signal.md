# decouple-signal
- The brief said the agreed requirements wording for durable signals was already in spec/requirements.md; it was only in issues/durable-signals.md (Requirements section), with the old welded line still in place. Applied the agreed wording.
- `claudewait` rejects an ID from a command whose redirect target directory did not exist (the command exited at once); make the log directory first.
