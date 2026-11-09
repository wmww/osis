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
/// each open epoch valid, listing the epochs on its line; every other epoch of `named` held
/// invalid, so a box naming it is stale and no box is sealed to it. An epoch that counts but is
/// closed is judged as one held invalid: a rotation closes epochs it does not supersede too.
pub fn account_keysets<E: Ord + Copy>(chain: &Chain<E>, named: &BTreeMap<E, Epoch>) -> Keysets {
    let mut out = Keysets::default();
    for (e, name) in named {
        if chain.open(e) {
            let line = chain.line(e).into_iter().flatten().filter(|x| *x != e).filter_map(|x| named.get(x)).copied().collect();
            out.valid.insert(*name, line);
        } else {
            out.invalid.insert(*name);
        }
    }
    out
}
