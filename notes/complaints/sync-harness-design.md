# sync-harness-design
- Counting crypto calls needed a throwaway counter patch in osis-crypto, rebuilding most of core twice (in and out): no call counter exists for sign/verify/AEAD/KEM. A `costs` span per crypto op would make this a test-side read.
- `tools/cpuprof` over a 0.4 s test gives about 150 samples: too few to split; profile a module in one process instead.
