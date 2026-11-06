# A departed holder still reading a label learns the fresh deposit seed
> Summary: spec/crypto.md §3 says a read rotation's fresh deposit seed stops a departed holder depositing, but the rotation commit is wrapped under the epoch it supersedes (§5), so a departed holder syncing that label opens it and reads the new `keys.0`.
> Tags: security, keys, node-sync

Repro: Dave's plain `t`, granted to group H and synced on its own (its own label); H's reader Bob reads `t`; Dave removes H (`set_role(t, H, None, ..)`); after sync Bob's `keys.0` of `t` has Dave's new `deposit_seed`. Bob got it from `t`'s own label, where the removal's body is. The whole body is one blob: the boxes need the old wrap, `keys.0` does not.

Holds only for a holder who read the removal under a label the commit's body goes to; one who read the thing through another label does not learn it (`tied::group_admin_learns_removal_elsewhere`, `tied::group_admin_copies_removal_without_new_keys`, `tied::group_removal_deposit_promoted_without_new_keys`, `tied::owner_home_copy_of_removal_without_new_keys`).

Other paths, by design of keysets reaching the labels of what an actor holds (spec/permissions.md §3, §4): a holder's new `keys.0` goes under its targets' labels, so a reader of target S learns holder T's current seed though it has no right on T (probe: Bob, reader of S, held T's newest seed after H left T); a departed holder still reading S does too. A revoke no longer brings the keyset of a thing no actor path connects to the label (`revokes::revoke_on_an_unrelated_thing_brings_no_keys`).

Cost of it: deposits under the thing's label up to its budget, no read or write. Needs: the seed out of the rotation commit's old-wrapped body (say sealed to the new epoch), or spec/crypto.md §3 dropping the claim.
