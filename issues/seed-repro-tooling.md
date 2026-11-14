# Some random node tests log no replayable script
> Summary: `memory_random_histories` and `memory_random_demotion` (osis-node ephemeral.rs) log their steps without clock advances, tick choices or delivery times, so a failing seed cannot be replayed or shrunk as a script; the window and churn runs' `Script`/`shrinking` shows the pattern.
> Priority: low
> Tags: tests, node
