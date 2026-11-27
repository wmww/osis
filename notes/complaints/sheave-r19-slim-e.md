# sheave-r19-slim-e
> Summary: Re-measuring slim-design figures needs a throwaway probe and a `tools/bin-at` baseline per job; a base moving mid-job made a figure look like a regression.

- The Today figures in notes/slim-design.md come from a throwaway sync probe (frames each way and rows per make over `growth::makes`), so each job writes it again and builds its merge base with `tools/bin-at --take` (about 5 minutes) to compare. A rebase onto another worker's commit mid-job moved the independent make by +2.5 KB, which read as this job's regression until a second `bin-at` at the new base. A by-hand `#[ignore]` probe kept in osis-sync `growth` (printing the Today table) would make both one command, and a coordinator could re-baseline after each landing.
