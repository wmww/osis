//! Requests from peers this module answers: Register and Delete (spec/sync-ids.md §6, taken by
//! the store's rules), Stranded and Suspect (spec/wire.md §11.2: answered Ok whatever the
//! receiver does with them).

use super::{Ground, Here, Net};
use crate::session::RequestId;
use crate::types::{ConnId, Credential};
use osis_proto::{Code, Msg};

pub(super) fn request<G: Ground>(h: &mut Here<'_, G>, net: &mut impl Net, conn: ConnId, id: RequestId, m: Msg) {
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
        // not built: the stranded holder's re-seal and the suspect repair they ask for
        // (spec/permissions.md §4) are judgement this node's engine makes
        Msg::Stranded { .. } | Msg::Suspect { .. } => Msg::Ok { id },
        _ => Msg::Error { id, code: Code::UNSUPPORTED },
    };
    net.answer(conn, id, reply);
}

/// A store credential: the head's sync key, a claim or a static entry (spec/sync-ids.md §6
/// Delete, spec/sync-opens.md §4).
fn store_credential(c: Credential) -> bool {
    matches!(c, Credential::SyncKey | Credential::Claim | Credential::Static(_))
}
