# forged-minting
- `Mutation::expires_all` covers only aspects written so far, not `create`'s `created.0`: a test minting "expiring" silently came out durable. Use `m.expires(t, &ct::CREATED, at)`.
- `Net::grant` on a plain thing does not reach the grantee's engine within `net.run()`/`advance` without inbox acceptance; ingesting the grant's package directly was the quick way.
- A minting applies only where the author's held edges reach the thing's record chain (`apply::thing_wait`), so "anyone holding the record may mint" needs an edge there in practice; tests must hand the victim that chain.
