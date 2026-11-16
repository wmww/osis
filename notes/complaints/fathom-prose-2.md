# fathom-prose-2
> Summary: Prose round 2 (engine notes, issues): what slowed the edit.

- Notes and issues cite function names that get renamed (`drop_left`, `throw_out`, `published_by_actor`, `await_reading`, `reads_in`); a throwaway scan of backticked snake_case names against the Rust sources found them in seconds. A tools/ check (warn on a cited `fn` name absent from the code) would keep them honest.
- Issues that grow into designs (history-less-grant at 35 KB with "Built:" in its Summary) hide what is left; move the design to a note once built.
