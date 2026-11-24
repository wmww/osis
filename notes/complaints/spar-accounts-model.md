# spar-accounts-model
> Summary: a wait for another job's landing sat idle for hours: the watch never fired though the landing was on main.

- Ready to land, blocked on the delete piece (policy refuses pointers into unlanded spec). A Monitor polling `git fetch` plus a grep of main's brief for the new heading stayed silent for 30 minutes, though the piece had long landed; the coordinator's status check found it. Likely the fetch failed inside the monitor with its error discarded. Would have prevented it: a `tools/` helper that waits for a commit (or a file's text) on origin/main and fails loudly when fetch fails, or briefs giving the dependent piece's landing as a channel message to wait for.
