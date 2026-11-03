# snapshot-cover
> Summary: the disk filled mid-task; a build and a commit failed with no warning.

- / hit 0 MB free during a tier-1 run: cargo errors read as compile failures and `git commit` failed. It cleared on its own. Worth a `df` before reading a build failure as a code one.
- `sim-sweep` has no way to print a failing seed's state: a throwaway probe in the scenario was the quick way to see why a body stayed uncovered.
