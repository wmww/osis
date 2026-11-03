# simplify-sync-review
- `-- --ignored parts::` also runs `parts::repro_body_class_move_drops_spec_commits_5`, ignored as a known hole, so it fails every time: the filter's exit code says nothing. Read test names.
- An oracle's default seeds passed through a main regression: `honest_flows_wait_for_no_resync` defaults to 0..2 and d56's fails from seed 4 (issues/honest-flows-fails-after-idle-pass.md). Each seed costs about 100 s under load.
