# stream-window
- The sim delivers each send alone, so no node test charged requests together; `Net::batch_reads` (opt-in) joins what a link carries before delivery. Defaulting it on would make every sim test see driver-like reads, but shifts every seed.
- Hostile shared-set tests send node-kind requests with small ids through `Command::Peer`: a check that node requests carry `NODE_IDS` ids broke eleven of them.
