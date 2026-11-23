# Nothing vouches for a role write
> Summary: Decided (Tess): a role write by a removed party that its remover's list does not name is dropped, whoever else received it; no vouch, automatic or otherwise, keeps it. A node that received it in time tells its user through the removal's result, and the user makes the change again as their own write. Built but the notice; to build: the notice.
> Priority: normal
> Tags: perm, engine, spec, tests

## The rule
- A role write of X that removal R of X does not list is invalid, as unlisted content with no addendum is (spec/permissions.md §5.1 Frontier: nothing but the frontier decides what X's writes before T survive).
- Content addenda (spec/permissions.md §5.2) are a separate mechanism and stay.
- **The notice**: a node holding a role write of X that R dropped, received in R's window, reports it in the removal's result (the `osis` API's account of a removal: what arrived unnamed and was discarded). Local only: nothing on the wire, no rule in the walk. The user's redo is an ordinary write by them, judged like any other; a removed key contesting it is an ordinary admin fight.
- Not built into core: waiting for a sync before writing a removal. An app may do it.

## Why no vouch can work
Two worlds hold the same commits and need opposite answers (roles-model `a_removal_the_remover_did_not_hold_is_undone` reads the first world by the rule): X removed N at 3, only B received it, H removed X listing nothing, and N's key backdates a removal of B to 2; or N honestly removed a stolen B at 2 and the thief, holding X's and B's keys, backdates X's removal of N and B's vouch. A witness's word counts by its standing, and the party it testifies against can always contest that standing with a backdated write.

Rejected: a witness's node making the write again unasked (modelled and dropped). Witnesses race, it fails safety in more worlds than vouches do, and nodes write role changes in their user's name without being asked.

## What users see
A share, pairing or removal X made shortly before X's own removal, which the remover's node had not received, is undone until someone redoes it; grants made under such a share in between are lost; the redo shows as the redoer's. A node in sync when it removes lists the change, and nothing is lost.

## To do
- **The notice** in the removal's result (notes/redesign-plan.md S3 brief 6).
