//! Requests from peers this module answers: Register and Delete (spec/sync-ids.md §6, taken by
//! the store's rules), Stranded (taken by the engine) and Suspect (spec/wire.md §11.2: answered Ok
//! whatever the receiver does with them).

use super::{Here, Net};
use crate::session::RequestId;
use crate::types::{ConnId, Credential};
use osis_proto::{Code, Msg};

pub(super) fn request(h: &mut Here<'_>, net: &mut impl Net, conn: ConnId, id: RequestId, m: Msg) {
    let reply = match m {
        Msg::Register { sync_id, step, claim_set, .. } => {
            // a store failure answers refused: the node reopens from its store
            let code = h.store.take_register(&sync_id, &step, claim_set.as_ref()).unwrap_or(Code::REFUSED);
            if code == Code::OK { Msg::Ok { id } } else { Msg::Error { id, code } }
        }
        Msg::Delete { sync_id, items, .. } => {
            let by_store = net.member(conn, &sync_id).is_some_and(|m| store_credential(m.by));
            let codes = h.store.take_delete(&sync_id, &items, by_store).unwrap_or_else(|_| vec![Code::REFUSED; items.len()]);
            Msg::Status { id, codes }
        }
        // judged by this node alone (`Engine::take_stranded`: only a current holder of an actor
        // it may re-seal, keys only along the holder's chain, one ask per holder and keys);
        // answered Ok whatever it does (spec/wire.md §11.2). A store failure loses the ask: the
        // reporter sends again once its step or its holder's keys move.
        Msg::Stranded { sync_id, holder, keys, .. } => {
            let _ = h.engine.take_stranded(&sync_id, &holder, &keys);
            Msg::Ok { id }
        }
        // not built: the suspect repair (issues/sync-suspect.md)
        Msg::Suspect { .. } => Msg::Ok { id },
        _ => Msg::Error { id, code: Code::UNSUPPORTED },
    };
    net.answer(conn, id, reply);
}

/// A store credential: the head's sync key, a sync proof (the peer's answer to this node's own
/// proof is keyed by S's sync proof), a claim or a static entry (spec/sync-ids.md §6 Delete,
/// spec/sync-opens.md §4).
fn store_credential(c: Credential) -> bool {
    matches!(c, Credential::SyncKey | Credential::SyncProof | Credential::Claim | Credential::Static(_))
}
