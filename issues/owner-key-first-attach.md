# A first owner key attached by an admin falls with that admin
> Summary: For Tess: an owner key a thing's admin attaches after the thing was made is undone when a later admin removes that admin and leaves the attach out of the removal's list, so the "attach a key, share adminship, take it back" flow fails in that one variant; keeping the key against that would let a stolen, removed node keep a thing by backdating an attach of its own key. Modelled meanwhile as option 1: the attach is an ordinary admin write.
> Priority: normal
> Tags: tess-call, perm, keys

Owner keys: notes/write-path-design.md, Owner keys (O4, O7, The flow that must hold); issues/recovery-redesign.md.

## The question
You attach an owner key to a thing you already administer, write it down, and make someone else an admin. That admin turns hostile and removes you, with a removal that does not list your attach. Should your owner key still work?

## Why it is not simply yes
A thing with no owner key takes its first from an admin, as an ordinary admin write. An ordinary admin write by a removed admin survives only if the removal lists it (nothing vouches for a role write). So the hostile admin's removal drops the attach, the thing has no owner key, and the hostile admin attaches its own.

The same commits appear in the opposite story: your node is stolen, a later-paired node removes it, and the thief backdates an attach of its own key to before the removal. There the attach must fall, or a removed stolen node keeps the thing for good. No rule reading only the commits can tell the two apart.

## The options
1. **The attach is an ordinary admin write** (designed, simple): a removed stolen node regains nothing. The take-back promise holds fully for a key the thing was made with, or one added by another owner key; for a key attached later by an admin it holds only while nobody removes that admin and leaves the attach out. Users who want recovery set the key when the thing (the account) is made; the API and UX say so.
2. **An admin whose grant began after the attach cannot undo it**: the promise holds for later-attached keys too, but a stolen node older than the node that removes it can backdate an attach past its own removal and keep the thing.
3. **Only at creation**: no first key from an admin at all. Simplest and safe, and removes "add recovery to an account I already have".

## Why users care
Option 1 makes "add a recovery key later" weaker than "create with a recovery key" in a way a user cannot see until a co-admin turns on them. Option 2 makes the oldest device of an account a permanent risk once stolen. Option 3 is honest and limiting.

Recommended: 1, with accounts made with a recovery key where the user wants one. Reversible: the rule is one clause of the walk (what a list write rests on).

In roles-model `paths` (notes/path-model-findings.md 55): option 1 is `Rules::fixed`, asserted by `an_attach_falls_with_its_attacher_where_the_removal_leaves_it_out`; option 2 is the one clause flipped (`Rules::attach_on_path` false, variant `-attach-kept`: the attach rests on its key hop alone), which keeps the key in that world and fails the story's safety where a stolen node backdates an attach of a key it made up (moves 54, 55).
