//! An account as a holder (spec/crypto.md §3, §4): the public name of its epochs, the keysets
//! other writers judge boxes to it by. Its role epochs stay internal to its nodes.

use crate::members::Keysets;
use crate::Error;
use osis_crypto::{Epoch, VerifyingKey};
use osis_perm::chain::Chain;
use std::collections::BTreeMap;

/// The name of an account's epoch: `[height, signing public key]`, known to outsiders from the
/// creation record, `keys.0` and the rotation header (spec/crypto.md §3).
pub fn account_epoch(height: u64, signing: &VerifyingKey) -> Result<Epoch, Error> {
    Ok(Epoch::new(height, signing.to_bytes())?)
}

/// An account's keysets as the seal and stale rules read them (spec/crypto.md §4, Account keysets):
/// each open epoch (a head) valid, listing the epochs on its line; every other epoch of `named`
/// sealed to by no one: `revoked` ones and those not counting held invalid, so a box naming one
/// is stale, the rest lasting (a rotation carrying no removal, a pairing's or a merge's, leaves no
/// one out of the epochs it closes, so a box there stays). The seal goes jointly at every head
/// (`Keysets::heads`): one outside the account; at a node of the account several only for its
/// devices' rotations made at once, which it cannot tell boxed to a removed node from the
/// others, so only a node holding every head opens the box.
pub fn account_keysets<E: Ord + Copy>(chain: &Chain<E>, named: &BTreeMap<E, Epoch>, revoked: impl Fn(&E) -> bool) -> Keysets {
    let mut out = Keysets { heads: true, ..Keysets::default() };
    for (e, name) in named {
        if chain.open(e) {
            let line = chain.line(e).into_iter().flatten().filter(|x| *x != e).filter_map(|x| named.get(x)).copied().collect();
            out.valid.insert(*name, line);
        } else if revoked(e) || !chain.epoch_counts(e) {
            out.invalid.insert(*name);
        } else {
            out.lasting.insert(*name);
        }
    }
    out
}
