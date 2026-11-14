# harness-tools complaints
> Summary: footguns met building the sync harness's trace, shrink budget and tools/mutate.py.

- The brief named a `watchdog` branch for the issues; it had already merged into sync-rebuild and been deleted, so `git show watchdog:...` failed. Briefs should name a commit or say "on sync-rebuild".
- A file restored with its old mtime (`shutil.copy2`) can make cargo keep the mutated build: tools/mutate.py writes the original text anew instead.
