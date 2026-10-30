# Expired links: backdated grants uploaded while every sharer device is offline stand
> Summary: Policy call for the owner. A link's `until` is enforced by a sharer device's removal of L after a complete pass of K's label ended after `until`; a backdated grant (signed as L, `ts` < `until`) uploaded after `until` but before that pass is covered and stands for good. Same when K's server is unreachable: no finalization until it is back. Alternative: cut at the server's receipt time.
> Tags: security, permissions, node, owner-call

Spec: spec/permissions.md §9 (finalization), notes/permissions.md (Finalization). Code: `SyncEngine::finalize_links`.

Window: from `until` to the first complete pass of K's labels by any sharer device (all devices offline, or K's server down: unbounded). In it, anyone holding the link text can join permanently. Honest late redeemers (clock skew, slow upload) are indistinguishable by `ts`.

Options:
- Keep (current): no honest joiner who redeemed before `until` by their clock and uploaded before the sharer's pass is lost.
- Server-attested receipt: the label server stamps entries with its receive time; the finalizer's frontier covers only L's commits received by the server before `until` (+ a skew allowance, an arbitrary value). Closes the window for honest servers; a colluding server reopens it. Needs a wire change (spec/sync.md).
- Short expiry warning in the API (`LinkOpts.until` docs): "enforced when a device of yours next syncs after it".
