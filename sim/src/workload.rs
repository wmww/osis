//! Random writes over a small schema with one aspect per merge encoding the engine builds today
//! (sequences wait for crdt-seq). Small value pools make concurrent writes collide.

use crate::dice::Dice;
use osis_core::{Tid, Value};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_node::{Mutation, Result};
use osis_schema::{Aspect, StaticSchema};

pub static SIM: StaticSchema = StaticSchema::new(
    "sim.osis",
    r#"
schema 0x51a0000000000000000000000000005a;
revision 1;
aspect /s/reg: string;
aspect /s/count: counter<int>;
aspect /s/hi: max<int>;
aspect /s/tags: set<string>;
aspect /s/map: map<string, int>;
"#,
);

pub const REG: Aspect<Value> = Aspect::new("/s/reg", &SIM);
pub const COUNT: Aspect<Value> = Aspect::new("/s/count", &SIM);
pub const HI: Aspect<Value> = Aspect::new("/s/hi", &SIM);
pub const TAGS: Aspect<Value> = Aspect::new("/s/tags", &SIM);
pub const MAP: Aspect<Value> = Aspect::new("/s/map", &SIM);

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
