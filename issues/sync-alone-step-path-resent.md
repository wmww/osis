# A holder of sync alone is sent the whole step path with each step
> Summary: `inbox::deliver_with_steps` owes a sync-alone holder a sealed copy of every `sync.0` write held with each step `deliver_step` sends it, so a long-lived thing costs O(path) copies per step, O(path²) over its life per holder.
> Priority: normal
> Tags: engine, sync, perf

`deliver_step` sends each step bearing a holder's sync key (and the first past them) with the target's other `sync.0` writes held, so the holder's readers can read the step from its records (a lone step delta joins nothing). A fire goes once taken, so the next step owes the whole path again: k steps while H's key stands cost about k²/2 sealed copies to H. Fresh steps (readers listed, link keys) do not rotate sync, so k grows with grants. The holder's readers keep the copies they took (rows of `su/`, logged under H's sync ID), so most of each resend is held there already. A fix sends what H's readers lack: e.g. the step and its ancestors back to one this node sent H or delivered in its grant, or a path H's readers ask for by the step they hold.
