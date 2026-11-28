# Recovery: a key that can take a thing back
> Summary: Parked (Tess, not imminent): no key outranks a thing's admins, so a key written down recovers a thing only while no admin removes it. A key that takes a thing back from its admins cannot be judged from commits alone: the owner's take-back and a thief's takeover are the same commits. Candidate: a waiting period counted from each node's receipt, during which admins are told and may cancel.
> Priority: low
> Tags: tess-call, perm

## What holds today
A signing key holds an ordinary grant on the thing it signs as (notes/write-path-design.md, Keys): admins write and remove it like any grant, and an admin key is one admin among the others. So a key written down gets a thing back after every node is lost, and loses to any admin that removes it first. A thing whose only admin is a lost key, or that has no admin, stays as it is.

## The problem
Wanted: a key its holder can use to take a thing back from the thing's admins (a stolen node, a co-admin turned hostile), which those admins cannot remove.

Two stories, the same commits:
- **Mine**: I add a key at 12:10, my laptop is stolen at 12:20, I take the thing back with the key at 12:30.
- **The thief's**: the laptop is stolen at 12:00, the thief adds a key at 12:10 and takes the thing over with it at 12:30.

In both an admin node adds a key and the key then removes that node's fellow admins. Stamps are the writer's word, so "the key was added before the theft" is nothing a reader can check, and whichever rule keeps my key keeps the thief's. No rule reading only the commits tells them apart: a key that outranks admins is a takeover tool for whoever holds an admin node for a moment.

The same shape, one step on: a key added by an admin that a later admin removes without listing the add. Keeping the key there lets a stolen, removed node keep a thing by backdating an add of its own key; dropping it undoes an honest owner's key (roles-model `paths`, `a_keys_grant_falls_with_its_grantor_where_the_removal_leaves_it_out`).

## Candidate: a waiting period
What differs between the stories is not in the commits: in mine the other admins' nodes saw the key added and nobody objected.
- Adding such a key makes every admin's node notify its user: "a key was added".
- For a window counted from each node's own receipt of the add (never from a stamp), any admin may cancel the add.
- After the window the key has its full effect at that node, and only such keys remove it.

The window is a picked number (notes/arbitrary-values.md): at 0 the key has full effect at once, so a thief holding a node wins; at infinity no added key ever takes effect, so only keys a thing was minted with count. It protects against a theft after the window, never one inside it, and each node counts its own window, so nodes differ on whether a key has taken effect until all have passed it (a fork like any admin dispute: notes/principles.md, Forks are permanent).

## To settle with Tess
- spec/requirements.md Concepts: a role can be changed or removed by those with the right to. A key no admin can remove fits only where some party (other such keys, a cancel in the window) holds that right.
- Whether a thing minted with a key gives that key the stronger standing from the start (the infinity end), and whether that standing can be given up.
- What a node that first syncs after the add counts its window from, and whether a node given another's recorded sides takes its receipt times.
- Who may cancel, and whether a cancel can itself be contested.
- A stolen recovery key: two parties holding one key cannot be told apart.
- Authority, not data: nothing is sealed to a key, so a key that takes a thing back reads again only what another reader re-seals to it.
