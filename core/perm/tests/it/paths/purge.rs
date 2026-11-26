//! The model's purge worlds (roles-model `paths::purge`, notes/purge-model.md): requests of every
//! class and selector by honest parties and by a thief, destructions, a cover's copies read by a
//! node holding only what was made after it, and an own cover whose writer is removed later,
//! each read at every node's view by the walk and by the model under `Rules::purging`.
//! spec/permissions.md §6, §5.2 Own cover;
//! spec/commits.md §4 Could hold the right, §5.

use super::{diff, rules};
use crate::common::{seeded, sharded};
use roles_model::paths as m;

/// Purge worlds `start..start + n` at every node (disputes in one world in ten); the failures,
/// at most three.
pub fn run(start: u64, n: u64, disputes: bool) -> Vec<String> {
    let mut fails = vec![];
    for i in start..start + n {
        let pw = m::purge_world(i, &rules());
        for node in pw.nodes() {
            let v = pw.view_at(node, None);
            if let Some(d) = diff(&pw.w, &v, disputes && i % 10 == 0) {
                fails.push(format!("purge world {i} node {node}: {d}\nheld {:?} trust {:?}\n{}", v.held, v.trust, m::purge_trace(&pw)));
                if fails.len() >= 3 {
                    return fails;
                }
            }
        }
    }
    fails
}

// spec/permissions.md §6: the walk reads the purge worlds at every node as the model does.
#[test]
#[ignore = "property"]
fn paths_purge_agree_plain() {
    let f = run(0, 300, true);
    assert!(f.is_empty(), "{}", f.join("\n"));
}

// spec/permissions.md §6: as above, a sample (a property).
#[test]
#[ignore = "property"]
fn paths_purge_agree_large() {
    let f: Vec<String> = sharded(100_000, 0x5eed_0a1e, |n, seed| run(seeded(seed) % (1 << 40), n, true)).concat();
    assert!(f.is_empty(), "{}", f.join("\n"));
}
