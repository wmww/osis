# Tier-2 new_device_alike_large fails on main
> Summary: `order::new_device_alike_large_spec_permissions_5_1` fails 13 of 256 seeds at main 72013fa7 (1, 19, 24, 52, 54, 95, 139, 149, 162, 177, 199, 217, 246): a fresh node after covered drops reads another value than one holding every body. Tier 1's 16-seed version passes.
> Tags: tests, engine

Seen while checking purge-rights, which fails the same seeds with the same counts. Shrunk seed 1: `t:map.0` every body `v8`, after covered drops `v4`; histories hold a demotion and a compaction. Not traced; the order file last changed with parts-holes and header-actor.
