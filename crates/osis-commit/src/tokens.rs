//! Delete tokens of a commit: token secrets by level, token hashes, chunk token hashes, blob
//! prefix inputs (spec/crypto.md §7, spec/wire.md §5).

use crate::header::{Kind, Token};
use crate::retention::token_levels;
use crate::Error;
use osis_core::Tid;
use osis_crypto::{Secret32, commitment, delete_token, token_hash};
use osis_schema::Retention;

/// Secrets a writer supplies (osis-keys and the node implement it).
pub trait Secrets {
    /// Dedup secret of a thing (spec/crypto.md §3).
    fn dedup(&self, tid: &Tid) -> Option<Secret32>;
    /// The thing's current admin secret (level 1).
    fn admin(&self, tid: &Tid) -> Option<Secret32>;
    /// The current write secret of the actor directly above the author node in its chain
    /// (level 2).
    fn chain_write(&self) -> Option<Secret32>;
    /// The thing's current write secret (level 3).
    fn write(&self, tid: &Tid) -> Option<Secret32>;
}

/// A token secret at its level.
#[derive(Clone, Debug, PartialEq)]
pub struct TokenSecret {
    pub level: u8,
    pub secret: Secret32,
}

impl TokenSecret {
    /// The token hash under a salt: BLAKE3(kdf("delete token", secret, salt))[..16].
    pub fn hash(&self, salt: &[u8; 16]) -> Token {
        Token { level: self.level, hash: token_hash(delete_token(&self.secret, salt).expose()) }
    }
}

/// Token secrets of a delta on `tid` with retention `r` in a commit of `kind`.
///
/// Provisional (issues/token-admin-secret.md): a writer that does not hold the thing's admin
/// secret omits the level-1 token, on a content delta and on a membership delta alike (an
/// invite grant, a self-removal, a writer's rotation or re-seal); any other missing secret is
/// an error.
pub fn token_secrets(s: &dyn Secrets, tid: &Tid, r: &Retention, kind: Kind) -> Result<Vec<TokenSecret>, Error> {
    let mut out = Vec::new();
    for level in token_levels(r, kind) {
        let secret = match level {
            1 => s.admin(tid),
            2 => Some(s.chain_write().ok_or(Error::Build("author-chain write secret not supplied"))?),
            _ => Some(s.write(tid).ok_or(Error::Build("thing write secret not supplied"))?),
        };
        if let Some(secret) = secret {
            out.push(TokenSecret { level: *level, secret });
        }
    }
    Ok(out)
}

/// Clear blob prefix inputs (spec/wire.md §5); osis-label lays them out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prefix {
    pub salt: [u8; 16],
    /// Expiry `T`, wall ms.
    pub expiry: Option<u64>,
    /// Strictly ascending 17-byte commitments.
    pub commitments: Vec<[u8; 17]>,
}

impl Prefix {
    /// Prefix of a commit blob from the header token hashes its parts call for.
    pub fn from_tokens(salt: [u8; 16], expiry: Option<u64>, tokens: &[Token]) -> Result<Prefix, Error> {
        let mut commitments = tokens.iter().map(|t| commitment(t.level, &t.hash, &salt)).collect::<Result<Vec<_>, _>>()?;
        commitments.sort_unstable();
        commitments.dedup();
        Ok(Prefix { salt, expiry, commitments })
    }

    /// Prefix of a chunk, tree-node or page blob: chunk tokens under its own salt.
    pub fn for_chunk(salt: [u8; 16], expiry: Option<u64>, secrets: &[TokenSecret]) -> Result<Prefix, Error> {
        let tokens: Vec<Token> = secrets.iter().map(|s| s.hash(&salt)).collect();
        Prefix::from_tokens(salt, expiry, &tokens)
    }
}
