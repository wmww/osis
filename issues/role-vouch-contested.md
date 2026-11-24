# Nothing vouches for a role write: the notice
> Summary: Decided (Tess): a role write by a removed party that its remover's list does not name is dropped, whoever else received it; no vouch keeps it. A node that received it in time tells its user through the removal's result, and the user redoes it as their own write. Built but the notice.
> Priority: normal
> Tags: perm, engine, api

## The rule
- A role write of X that removal R of X does not list is invalid, as unlisted content with no addendum is (spec/permissions.md §5.1 Frontier). Content addenda (§5.2) are a separate mechanism and stay.
- **The notice** (to build, notes/redesign-plan.md S3): a node holding a role write of X that R dropped, received in R's window, reports it in the removal's result in the `osis` API (what arrived unnamed and was discarded). Local only: nothing on the wire, no rule in the walk. The redo is an ordinary write by the user; a removed key contesting it is an ordinary admin fight.
- Not in core: waiting for a sync before writing a removal. An app may.

## Why no vouch can work
Two worlds hold the same commits and need opposite answers (roles-model `a_removal_the_remover_did_not_hold_is_undone`): X removed N at 3, only B received it, H removed X listing nothing, and N's key backdates a removal of B to 2; or N honestly removed a stolen B at 2 and the thief, holding X's and B's keys, backdates X's removal of N and B's vouch. A witness's word counts by its standing, which the party it testifies against can always contest with a backdated write. Rejected too: a witness's node making the write again unasked (races, fails safety in more worlds, and writes role changes nobody asked for).

## What users see
A share, pairing or removal X made shortly before X's own removal, which the remover's node had not received, is undone until someone redoes it; grants made under it meanwhile are lost; the redo shows as the redoer's. A node in sync when it removes lists the change, and nothing is lost.
