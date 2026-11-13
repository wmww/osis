# An account's signing-chain fork is merged by one designated node
> Summary: a fork of an account's signing chain is merged only by the node whose rotation is the lowest authorized head (spec/permissions.md §5.5, Honest nodes of P; `flows::signing::merger`). If that node is gone for good (factory reset, lost while still on the devices roster), nothing merges the fork: the rotations off the followed line are never answered by a merge, so what that requires (listing the commits those rotations close, naming the fork) waits on one specific device.
> Priority: normal
> Tags: keys, perm, accounts

## Shape
The same pattern as the role merger that joint sealing removed (notes/crypto.md, Forks stand): a designated party any of whose devices may vanish. Holder-actor sealing no longer needs the account's fork merged (an account anchored at two heads is sealed jointly), so what still depends on the chain merge is the account's own bookkeeping: listings of commits at closed epochs (spec/permissions.md §5.5, Listings: "a rotation off it is answered by the merge ending the fork"), doubt (§5.4), and naming forks (issues/write-at-removed-nodes-rotation-lost.md).

## To study
- What a standing chain fork actually costs when nobody merges it (which commits fail to count, at which nodes).
- Whether any node of P may merge where identical inputs give identical merges, or whether listings can answer a fork without a merge.
