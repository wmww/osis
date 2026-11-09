# A pump that does not end after a direct link expires
> Summary: Two online nodes of one account with no saved peers, one holding a direct link past its `until`: a `World` pump keeps running past 280 s without a storm panic, passes busy in `local_pass`. Not traced; whether it is a message loop or passes that grow is open.
> Priority: normal
> Tags: node, sync, tests

Reproduce: core/test/sim/tests/it/no_server.rs `repro_row37_another_node_of_the_sharer_finalizes_a_link`, without its `w.set_online(&a, false)`, so the maker stays online past `until`. A stack taken during the run was in `judge_local`/`body_keeps`, under `run_dirty`.
