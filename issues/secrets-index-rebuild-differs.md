# The secrets index rebuilt from the commit records differs from the live one
> Summary: osis-cli `cli::sharing_commands_local_plan_cli_4` fails on main at the store-reload check: the `secrets` table loaded afresh holds sync epochs 1 and 2 of a thing whose live index holds only epoch 3; cause not found.
> Priority: normal
> Tags: engine, tests

`cli::sharing_commands_local_plan_cli_4` fails every run (also at 02e524738, before the stub rewrite's R5a): `engine/mod.rs` index check, "rebuilt from the commit records (want: this node's live index, got: its store loaded afresh), the index Table(\"secrets\")". For one thing the reloaded index holds `sync` epochs 1 and 2 with secrets beside epoch 3, the live one epoch 3 alone (its rotation listed, no secret). Either the live index drops superseded sync secrets the store keeps, or the reload reads secrets the live node let go. Not yet in a smaller test.
