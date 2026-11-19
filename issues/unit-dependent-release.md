# Does a unit let go of a dependent thing it no longer references?
> Summary: With a sync unit being one independent thing and its dependents, either a unit holds a dependent thing only while it references it (then a reference from another unit cannot keep a dependent thing alive), or it holds every dependent thing ever made in it (then nothing made in a unit is ever released). Each breaks a line of spec/requirements.md; Tess picks. The plan proceeds on the first.
> Priority: normal
> Tags: tess-call, sync, engine, spec

## The question
A thing X is made inside a realm H (dependent: it shares H's keys). Later H stops referencing X. Should X go, even if a thing outside H (your home) still references it strongly?

It has to be one or the other. A thing is stored under one unit only, and everyone holding that unit must agree on what it holds from the unit's own data. References from other units are not in that data.

## The two rules
1. **A unit holds a dependent thing while the unit itself references it** (what is built today for dependent things, and the design in notes/sync-unit-design.md §6).
   - A user sees: remove a thing from the realm and it goes everywhere, as now. A bookmark to it from your own home then points at nothing, with the existing "not carried" warning. Had the thing been independent (shared on its own), the bookmark would have kept it.
   - Whether the outside strong still brings the realm's unit then depends on history: it does where a member blob was logged while the realm reached the thing, not otherwise (notes/closure-model.md, Finding B, `pin_a_strong_to_a_dependent_its_unit_dropped`).
   - Breaks: "nothing an app can observe depends on how osis keys a thing" (API) and "a thing takes with it the part of its closure it can itself sync" (Data model), in that one corner: a reference from another unit to a dependent thing its own unit dropped.
2. **A unit holds every dependent thing made in it, referenced or not** (notes/closure-model.md, control `Unit::All`).
   - A user sees: nothing made in a realm or an account ever leaves any node that syncs it, until someone destroys it. Removing a reference frees no storage. A bookmark from outside always works.
   - Breaks: "a thing is kept while something references it strongly and released when nothing does" (Data model), "nothing syncs for having been created with some admin" (Offline and network), and "making and releasing things again and again does not grow a node's storage without bound" (Scale).

## Recommendation
Rule 1. It keeps storage following what is referenced, which users rely on everywhere; its cost is one corner with a warning and a way out (make the thing independent, which sharing it does, and the outside reference keeps it). If accepted, the requirements item on promotion says so: a reference from outside a thing's unit keeps the thing only once it is independent.

## Meanwhile
The plan (notes/redesign-plan.md, M1, B2) proceeds on rule 1: it is what the spec and engine already do for dependent things, so B2 keeps that code instead of deleting it. Going to rule 2 later is a deletion (the release of dependents inside a unit, and its model property); nothing else changes.
