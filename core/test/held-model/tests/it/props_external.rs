//! Properties of the external-fire rule (spec/permissions.md §5.2 External fires, spec/commits.md §5
//! The setting, spec/sync-inbox.md §4) over `held_model::external` worlds: every subset of a
//! world's events is a held set, so every arrival order of them is covered.
use held_model::edits::listed_of;
use held_model::external::*;
use held_model::gen::shuffle;
use held_model::*;
use std::collections::BTreeMap;

const SEEDS: u64 = 40;

/// Each held set of seed `seed`'s world, as node `me` holds it under `rule`.
fn held_sets(seed: u64, me: NodeId, rule: ExternalFires) -> Vec<Held> {
    let w = world(seed);
    (0..1u64 << w.events.len()).map(|m| w.held(m, me, rule)).collect()
}

/// The fires of `EXT` applied, and whether each is valid.
fn fires(h: &Held, o: &Outcome) -> BTreeMap<CommitId, bool> {
    h.commits.iter().filter(|c| c.parts[0].aspect == EXT && o.applied.contains(&c.id)).map(|c| (c.id, o.valid[&(c.id, 0)])).collect()
}

/// The thing's current setting: its newest held valid one (spec/commits.md §5 In force).
fn current(o: &Outcome) -> Option<&(Key, Setting)> {
    o.settings.get(&THING).and_then(|v| v.last())
}

fn enables(s: &Setting) -> bool {
    s.rules.iter().any(|r| r.0 == EXT.name)
}

/// Every node holding the same set judges every fire alike, whatever order it holds them in.
fn alike_in_every_order(rule: ExternalFires, seeds: u64) -> Result<(), String> {
    for seed in 0..seeds {
        for h in held_sets(seed, ADMIN, rule) {
            let want = fires(&h, &evaluate(&h));
            for k in 0..3 {
                let s = shuffle(&h, seed * 31 + k);
                if fires(&s, &evaluate(&s)) != want {
                    return Err(format!("seed {seed}: order {k} judges the fires otherwise than {want:?}"));
                }
            }
        }
    }
    Ok(())
}

/// Seen while checking `unnamed_fires_go_nowhere` under the rule: each shape the brief names.
#[derive(Default, Debug)]
struct Seen(BTreeMap<&'static str, usize>);

impl Seen {
    fn add(&mut self, what: &'static str, yes: bool) {
        *self.0.entry(what).or_default() += yes as usize;
    }
}

/// A fire its author's authority does not make valid (a party holding no write) and the current
/// setting does not enable reaches no listener (is listed nowhere) and is not promoted; one it
/// enables is valid; a writer's fire is judged alike with every setting gone.
fn unnamed_fires_go_nowhere(rule: ExternalFires, seeds: u64, seen: &mut Seen) -> Result<(), String> {
    for seed in 0..seeds {
        for h in held_sets(seed, ADMIN, rule) {
            let (o, tl) = judged(&h);
            let listed = listed_of(&h, &o);
            let cur = current(&o);
            let named = cur.is_some_and(|(_, s)| enables(s));
            let unset = Held { commits: h.commits.iter().filter(|c| c.parts[0].aspect != Aspect::RETENTION).cloned().collect(), ..h.clone() };
            let unset = fires(&unset, &evaluate(&unset));
            for c in h.commits.iter().filter(|c| c.parts[0].aspect == EXT && o.applied.contains(&c.id)) {
                let writer = tl.valid_delta(c, THING, EXT);
                let valid = o.valid[&(c.id, 0)];
                if !writer && !named && (promotes(&o, c, 0) || listed.contains(&c.id)) {
                    return Err(format!("seed {seed}: unnamed fire {} by {} promoted or listed (held {:?})", c.id, c.author, ids(&h)));
                }
                if (writer || named) && !valid {
                    return Err(format!("seed {seed}: fire {} by {} invalid though {}", c.id, c.author, if writer { "its author writes" } else { "enabled" }));
                }
                if writer && unset.get(&c.id) != Some(&valid) {
                    return Err(format!("seed {seed}: a writer's fire {} judged by the setting", c.id));
                }
                let removal = h.commits.iter().any(|x| x.is_role() && matches!(x.parts[0].body, Body::Held(Delta::Edge(EdgeWrite { holder: WRITER, role: None, .. }))));
                let stranger = !writer && c.author == STRANGER;
                let enabling = o.settings.get(&THING).is_some_and(|v| v.iter().any(|(_, s)| enables(s)));
                seen.add("enabled then fired", stranger && valid && cur.is_some_and(|(k, _)| *k < c.key()));
                seen.add("fired then enabled", stranger && valid && cur.is_some_and(|(k, _)| *k > c.key()));
                seen.add("disabled after a fire", stranger && !valid && enabling);
                seen.add("a writer's fire, not enabled", writer && c.author == WRITER && !named);
                seen.add("a removed writer's fire", !writer && c.author == WRITER && removal);
                // the admins' dispute: a newer held setting is invalid, so another one is current
                let newer_fell = h.commits.iter().enumerate().any(|(_, x)| x.parts[0].aspect == Aspect::RETENTION && o.applied.contains(&x.id) && !o.valid[&(x.id, 0)] && cur.is_some_and(|(k, _)| x.key() > *k));
                seen.add("a setting fallen in the admins' dispute", stranger && newer_fell);
            }
        }
    }
    Ok(())
}

/// A held setting that is not current dropping (out of history, never received) changes no
/// fire's validity: the rule reads the current setting alone.
fn older_settings_drop_freely(rule: ExternalFires, seeds: u64) -> Result<(), String> {
    for seed in 0..seeds {
        for h in held_sets(seed, ADMIN, rule) {
            let o = evaluate(&h);
            let want = fires(&h, &o);
            let Some(((_, _, cur), _)) = current(&o) else { continue };
            for k in 0..h.commits.len() {
                let c = &h.commits[k];
                if c.parts[0].aspect != Aspect::RETENTION || c.id == *cur {
                    continue;
                }
                let mut d = h.clone();
                d.commits[k].parts[0].body = Body::Missing;
                if fires(&d, &evaluate(&d)) != want {
                    return Err(format!("seed {seed}: setting {} dropping changes the fires {want:?}", c.id));
                }
            }
        }
    }
    Ok(())
}

fn ids(h: &Held) -> Vec<CommitId> {
    h.commits.iter().map(|c| c.id).filter(|&id| id < 1000).collect()
}

// spec/permissions.md §5.2 (External fires), spec/commits.md §5 (In force), §4 (Order
// independence): validity of every fire is a function of the held set, in every arrival order
#[test]
fn external_fires_are_judged_alike_in_every_order_spec_perm_5_2() {
    alike_in_every_order(ExternalFires::Enabled, SEEDS).unwrap();
}

// spec/permissions.md §5.2 (External fires), spec/sync-inbox.md §4 (Promotion), spec/commits.md
// §7 (Listed parts): an unnamed fire by a party holding no write reaches no listener and is never
// promoted; an enabled one is valid; a writer's fire does not read the setting. The worlds reach
// each case the rule turns on.
#[test]
fn unnamed_external_fires_reach_no_listener_and_are_not_promoted_spec_perm_5_2() {
    let mut seen = Seen::default();
    unnamed_fires_go_nowhere(ExternalFires::Enabled, SEEDS, &mut seen).unwrap();
    eprintln!("{seen:?}");
    for (what, n) in &seen.0 {
        assert!(*n > 0, "no {what} in {SEEDS} worlds");
    }
    assert_eq!(seen.0.len(), 6);
}

// spec/commits.md §5 (In force; Out of history): the current setting alone decides, so an older
// setting's body dropping changes no fire
#[test]
fn older_settings_dropping_changes_no_external_fire_spec_commits_5() {
    older_settings_drop_freely(ExternalFires::Enabled, SEEDS).unwrap();
}

// Negative controls (spec: none): each property fails on a rule that breaks it. Arrival order
// deciding which setting is in force breaks order independence; no rule (today's `Any`) promotes
// an unnamed fire; the setting in force at the fire's key lets a fire stamped before a disabling
// setting stand, and turns a fire invalid when the setting before it drops.
#[test]
fn external_fire_properties_have_negative_controls() {
    assert!(alike_in_every_order(ExternalFires::Arrival, SEEDS).is_err(), "arrival order");
    assert!(unnamed_fires_go_nowhere(ExternalFires::Any, SEEDS, &mut Seen::default()).is_err(), "no rule");
    let at_key = unnamed_fires_go_nowhere(ExternalFires::AtKey, SEEDS, &mut Seen::default());
    eprintln!("at key: {at_key:?}");
    assert!(at_key.is_err(), "at key");
    let dropped = older_settings_drop_freely(ExternalFires::AtKey, SEEDS);
    eprintln!("at key, dropped: {dropped:?}");
    assert!(dropped.is_err(), "at key, an older setting dropped");
}
