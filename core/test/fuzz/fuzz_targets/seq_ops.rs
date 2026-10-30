//! Sequence op scripts (spec/crdt.md §4.5, §4.6, §5.7, §6, §8): an `arbitrary` script of local
//! ops (insert, delete, move, paste, edit, set; several in one commit, skewed clocks), model
//! commits, undos, joins in any order with duplicates, snapshot round trips and bootstraps on
//! three replicas of one text or list, replayed by `osis_crdt::fuzzing::replay`: against the
//! reference model (core/test/crdt-model), a plain sequence, one-by-one commits, the wire (bytes
//! identical), placements held in part (ops and joins) and every debug comparison in the crate.
#![no_main]

use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;
use osis_crdt::fuzzing::{LocalOp, Script, Step, replay};

#[derive(Arbitrary, Debug)]
struct FScript {
    list: bool,
    steps: Vec<FStep>,
}

#[derive(Arbitrary, Debug)]
enum FStep {
    Ops { r: u8, ops: Vec<FOp>, skew: u8, per: u8 },
    Model { r: u8, seed: u16 },
    Undo { r: u8, back: u8 },
    Join { to: u8, pick: u8, n: u8, per: u8, merged: bool },
    Reboot { r: u8 },
    Bootstrap { r: u8, from: u8 },
}

#[derive(Arbitrary, Debug)]
enum FOp {
    Insert { at: u16, item: u8 },
    Delete { at: u16, len: u8 },
    Move { at: u16, len: u8, to: u16 },
    Paste { run: u8, at: u16 },
    Edit { at: u16, del: u8, item: u8, stale: bool },
    Set { item: u8 },
}

fn op(o: FOp) -> LocalOp {
    match o {
        FOp::Insert { at, item } => LocalOp::Insert { at, item },
        FOp::Delete { at, len } => LocalOp::Delete { at, len },
        FOp::Move { at, len, to } => LocalOp::Move { at, len, to },
        FOp::Paste { run, at } => LocalOp::Paste { run, at },
        FOp::Edit { at, del, item, stale } => LocalOp::Edit { at, del, item, stale },
        FOp::Set { item } => LocalOp::Set { item },
    }
}

fn step(s: FStep) -> Step {
    match s {
        FStep::Ops { r, ops, skew, per } => Step::Ops { r, ops: ops.into_iter().map(op).collect(), skew, per: per % 9 },
        FStep::Model { r, seed } => Step::Model { r, seed },
        FStep::Undo { r, back } => Step::Undo { r, back },
        FStep::Join { to, pick, n, per, merged } => Step::Join { to, pick, n, per: per % 9, merged },
        FStep::Reboot { r } => Step::Reboot { r },
        FStep::Bootstrap { r, from } => Step::Bootstrap { r, from },
    }
}

fuzz_target!(|s: FScript| {
    replay(&Script { list: s.list, steps: s.steps.into_iter().map(step).collect() });
});
