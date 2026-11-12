# A reader can grow every label carrying a thing's record by minting it again
> Summary: A thing's held mintings travel with its record as header-only copies (spec/commits.md §5), and anyone whose edges reach a thing's record chain (a reader of it) may mint it again any number of times. Each minting again becomes one more header copy, placed by honest nodes under every label carrying the record, labels the minter cannot write: k mintings give k copies per label (counted: 7 headers at 1 minting again, 16 at 10, for one record). The cert set also pulls in each minter's chain.
> Priority: normal
> Tags: security, engine, node-sync

- Destruction reads only whether every held minting is value-less, so a live thing needs one witness: its minting value-less last (durable first, then the latest `expires`; ties by commit ID). Direction: a live thing's record carries that one; a destroyed one its destroying requests and its latest-expiring minting. Check the purge case: a request that drops the witness but not a minting it has no right over (`nobody`, another's `author`) changes the witness, and the sender places the next.
- Destroyed things carry every held minting too, so the same growth applies to them.
