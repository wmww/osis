//! Random writes over a small schema with one aspect per merge encoding the engine builds today
//! (sequences wait for crdt-seq). Small value pools make concurrent writes collide.

use crate::dice::Dice;
use osis_base::{Tid, Value};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_node::{Mutation, Result};
use osis_schema::{Aspect, StaticSchema};

pub static SIM: StaticSchema = StaticSchema::new(
    "sim.osis",
    r#"
version 1;
aspect s:reg.0: string;
aspect s:count.0: counter<int>;
aspect s:hi.0: max<int>;
aspect s:tags.0: set<string>;
aspect s:map.0: map<string, int>;
aspect s:gone.0: string [by: writer];
aspect s:note.0: string;
aspect s:story.0: set<string>;
aspect s:latest.0: string [by: writer, keep_at_most: 0s];
"#,
);

pub const REG: Aspect<Value> = Aspect::new("s:reg.0", &SIM);
pub const COUNT: Aspect<Value> = Aspect::new("s:count.0", &SIM);
pub const HI: Aspect<Value> = Aspect::new("s:hi.0", &SIM);
pub const TAGS: Aspect<Value> = Aspect::new("s:tags.0", &SIM);
pub const MAP: Aspect<Value> = Aspect::new("s:map.0", &SIM);
/// Purgeable by any writer (scenarios only; random writes leave it alone).
pub const GONE: Aspect<Value> = Aspect::new("s:gone.0", &SIM);
/// A scenario's story marks (random writes leave it alone).
pub const STORY: Aspect<Value> = Aspect::new("s:story.0", &SIM);
/// Written with an expiry (scenarios only).
pub const NOTE: Aspect<Value> = Aspect::new("s:note.0", &SIM);
/// Kept at most 0 after replaced: only the latest value (scenarios only).
pub const LATEST: Aspect<Value> = Aspect::new("s:latest.0", &SIM);

const WORDS: [&str; 5] = ["ash", "birch", "cedar", "dogwood", "elm"];

fn word(d: &mut Dice) -> Value {
    Value::Str(d.pick(&WORDS).copied().unwrap_or("ash").into())
}

fn root(op: Op) -> PathOp {
    PathOp { path: Vec::new(), op }
}

/// Adds one random op on `t` to `m`.
pub fn random_op(d: &mut Dice, m: &mut Mutation, t: Tid) -> Result<()> {
    match d.below(10) {
        0 | 1 => m.set(t, &REG, &word(d))?,
        2 => m.op(t, &COUNT, root(Op::Inc(Value::Int(d.range_i64(-2, 5)))))?,
        3 => m.op(t, &HI, root(Op::Inc(Value::Int(d.range_i64(0, 1000)))))?,
        4 => m.op(t, &TAGS, root(Op::Add(word(d))))?,
        5 => m.op(t, &TAGS, root(Op::Remove(word(d))))?,
        6 => m.op(t, &MAP, PathOp { path: vec![PathSeg::Key(word(d))], op: Op::Set(Value::Int(d.range_i64(0, 9))) })?,
        7 => m.op(t, &MAP, root(Op::Remove(word(d))))?,
        8 => m.replace(t, &REG, &word(d))?,
        _ => match d.below(3) {
            0 => m.remove_aspect(t, &TAGS)?,
            1 => m.remove_aspect(t, &MAP)?,
            _ => m.remove_aspect(t, &REG)?,
        },
    };
    Ok(())
}
