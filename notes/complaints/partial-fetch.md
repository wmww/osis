# partial-fetch
> Summary: Mishaps on the newest-first fetch branch.
- `scale::long_aspect::first_sync`'s "fresh member" had a cursor (it went offline after one `net.run`), so the bench never measured a new device's replay. Fixed: offline before the first run.
- The sim's clock does not move between writes: an order of wall ms alone ties every message; found only by the bench (hence the whole `ts`).
- A status check in a test (`idle < open`) stayed true past the fill's end while a pass was wanted: a mutation looked caught when it was not. Assert on the data (`held < N`).
