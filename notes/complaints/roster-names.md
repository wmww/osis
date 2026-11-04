# roster-names
- The brief's two directions both fail for a reason visible in one spec line (a person's nodes are its admins), so most of the task was finding a third rule; a brief for a design task could ask "which actors can write M's `keys.0`" up front.
- TLC's "Unknown operator" error for a definition used before it is declared cost one round; TLA+ has no forward references, so new helpers go above their first use.
- Box at load 35-45 while the four larger TLC instances ran (3 workers each); their times in the README are wall clock at that load.
