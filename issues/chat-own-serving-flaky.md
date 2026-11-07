# chat own-serving test flaky under load
> Summary: `osis-chat` `thin::own_serving_node_takes_a_chat_spec_data_model_9` timed out at load ~35 with the chat's group `Refused` by the own serving node `mem://h` (20 s wall wait); passed alone in 1.2 s.
> Tags: tests, chat

Seen in a `tools/gate.sh` run on a branch touching only held-model and osis-node tests (retention-model review), box load 33-40. The status at the timeout: `GroupSync { state: Refused, refused_by: [mem://h], last_sync: None }`: the host still refused the new label after the 100 ms retry window the test sets, so it never learned the record, or the retry stopped. Asserts on wall time (`W`), which tier 1 should not. Not reproduced yet; first step: run it in a loop beside a loaded box and see whether the refusal ever clears.
