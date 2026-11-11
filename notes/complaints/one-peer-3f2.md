# one-peer-3f2
- `Mutex<HostStore>` cannot implement an osis-store trait in osis-host (orphan rule): the trait pair is `Ciphertext` (blanket over `Mutex<T: CipherHost>`) plus `CipherHost`, which the host implements.
- The sim, node `Net` and osis `MemStore::backup` all opened a fresh hub store per boot or left it out of backups; harmless while it held only others' data, data loss once the engine's blobs live there. Any new harness that restarts a node must keep both disks.
