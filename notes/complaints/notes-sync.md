# notes-sync
- sync.md lines run to 10 KB each: `sed -n` and Read both overflow; had to split the file into scratch pieces to read it.
- Code and API names drifted from the note unnoticed (`GroupSync::not_admitted`, `ReceiptsOnly`, `NoRoute`, `Config.peers`, `sync/ephemeral.rs`): a backticked-identifier check against `git grep` found them in seconds; worth a periodic tool.
