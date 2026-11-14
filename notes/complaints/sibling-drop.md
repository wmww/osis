# sibling-drop
- The rule-test delivery cap (RULE_CAP 2000) counts a whole World: each `run` while a node is partitioned costs ~850 deliveries (dials every 30 s over the hour horizon), so two such runs storm. Use `flush` while partitioned.
- The rebuilt driver never runs the lost-access trigger; notes/engine-lost-access.md still described node-sync's `drop_left` as if live.
