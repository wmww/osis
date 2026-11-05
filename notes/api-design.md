# API design philosophy
> Summary: Tess's rules for the public `osis` API (simple, complete, consistent, robust; the fewest concepts; no leaks; things named for what they are; never two ways to do one thing; churn welcome), the standing rules collected from other notes, and a checklist for every API addition or edit. notes/api.md is the shape as it stands; this note is how to judge it.

Applies to any change to what the `osis` crate exports, and to whatever else apps or the CLI's users see of it.

## Goals (Tess)
- **Simple**: an absolute bare minimum of concepts exposed.
- **Complete**: everything an app could reasonably want to do is possible. It need not be sleek or compact; a few more lines beat another concept or another function.
- **Consistent**: one concept has one word and one shape everywhere. Having used part of the API, you can guess the rest.
- **Robust**: every call behaves predictably, and failure is visible.

## Rules
- **One way.** There are never two ways to do one thing without a very good reason, written down at the definition. When a new call covers an old one, the old one goes in the same change.
- **Step back.** Before adding to the API, look at the whole area and how it should feel to use. The easy move, adding a function or a knob to what exists, is how every problem below arrived.
- **No leaks.** Things inside the core stay inside, however easy they are to expose. A word from the implementation (a label, an epoch, a frontier, a rotation, a compaction snapshot) needs a reason an app must know it. Sizes, caps and tuning constants of the implementation are not API.
- **Name what a thing is, not its common use.** A host is a host, even when it is a sometimes-on laptop with no public IP; never a "server". An address that can name a node is not a `HostAddr`. Spell words out over abbreviations.
- **Churn is good.** Until Tess opens the stability discussion, renames and reshaping are cheap and welcome. Call counts in tests are never a reason to keep a shape.

## Public docs
What `cargo doc` shows is for someone who has never seen this project.
- Say what a thing is and does, in plain words. Don't restate its name or where it sits ("the public API" of the crate you just opened; "layer 8").
- Don't lean on internals to explain ("over the node engine").
- No lists of undefined terms: they tell a new reader nothing.
- Rendered docs never cite notes/ or issues/; ordinary comments may. API users mostly need not care how things are implemented, so a spec reference is rarely wanted; where one really helps, link it if possible.
- Less is more. Don't define every word; often the fix is to say less. Judge each case.

## Patterns to flag and fix
- `do_x()` beside `do_y()`, where Y is a superset of X: remove `do_x()`.
- Two functions that should be one generic one.
- One function with many knobs that should be several. Tell-tale signs: a field that applies only to some calls, fields that override each other, or doc text that says "only when" or "ignored unless".
- A function centered wrongly: `do_x(actually_do_y: bool)` should be `do_z(x_or_y: enum)`.
- A convenience wrapper over another public call.
- One operation under two names, or two operations under one name.
- An argument with a magic value, such as an empty list meaning "the default".

## Choosing a shape
The right shape drifts as an area grows, and adding to what exists is always easier than refactoring. So re-decide the shape whenever an area changes; don't inherit it. The usual choices are enum or options struct, one function taking an enum or several functions, builder or plain struct, trait or concrete type, and callback or returned handle. No shape is right in general. These tests decide each case:
- Could any value be built that means nothing? Fields that exclude each other want an enum; fields that vary independently want a struct.
- Does the return type or the contract change with the argument? Then these are separate functions. If only the target changes, it is one function with an enum.
- Do similar calls in this API use the same shape? A different shape needs a reason.
- Can the compiler reject the misuse? Prefer that over a runtime `Invalid`.

## Standing rules
Collected from notes/api.md and notes/client-port.md and spec/requirements.md (API).
- **Plain values and listeners**, no CRDT concepts, no conflict UI. A lost concurrent write looks like any last-writer-wins loss. No correctness depends on surfacing something to a user; diagnostics are informational.
- **Untyped access works** on any stored data. Large values are usable both materialized and streamed; there must be tools to read, edit and listen to one without materializing it.
- **Local and synchronous.** Every data operation completes against the local store with nobody online, so it is a plain synchronous call. Only what waits for another node is `async`, and those futures are runtime-agnostic.
- **Explicit where a wrong default is silent.** Where a default is safe, default it.
- **One `Error` enum** with stable categories. What is absent reads as `None`. Stored data never fails a read on typed grounds: another writer's odd value reads as `None` with a `Mismatch` diagnostic. Peer-caused problems are diagnostics, never errors.
- **Never faked.** A call that cannot be answered says so. A connection failure is `Network`, never another source's answer and never a default value. A call that may fail returns `Result`.
- **Listeners fire for local changes too**, in commit order, after the commit is durable. No callback runs under a lock, and any API call is allowed inside a callback.
- **Rights are checked locally** before signing: a write is never emitted to be un-merged elsewhere.
- **Verifiable authorship only** (notes/api.md Attribution).
- **Engine access is not app API.** The CLI's `inspect`, the sim and test harnesses go through doc-hidden `osis::internals`. Anything only tests need lives there, not in the app API.

## Checklist for an API change
1. Can an existing call do this, perhaps generalized? Then generalize it; don't add one.
2. Does this make an existing call redundant? Remove that call in this change.
3. Is every new word necessary, and is it the word already used for this concept? (Vocabulary: notes/api.md.)
4. Does anything expose an internal concept, or a number an app has no use for?
5. Is the shape still right for the whole area, by the tests above?
6. What happens on an attached handle, offline, on a deleted thing, and with an empty argument? Is each predictable and visible?
7. Update notes/api.md and the doc examples in `core/osis/src/lib.rs`; picked numbers pass notes/arbitrary-values.md.
