# A read keyset no admin vouches for holds outside fires pending until an admin acts
> Summary: Outside fires seal to the admin's read key only while `keys.0`'s read keyset is of its epoch; a writer's keyset no admin holds current (junk, a lockout, a copy of a superseded epoch) holds every outside fire pending until an admin rotates read or removes the writer, and nothing makes that rotation due.
> Priority: low
> Tags: security, sync, keys

- Visible to the sender (pending, never "sent"), and no fire is lost; recovery is the lockout one (notes/keys.md Lockouts: the admin removes the writer, whose removal rotates read).
- An automatic trigger would be: an admin that may rotate read and holds the keyset's commit whole, at the end of a complete pass, rotates read when it cannot vouch for the keyset's epoch (FireKey.tla `ARotUnv`, assumed fair in `FK_live`). Cost: a hostile writer can make the admin rotate at will, and an admin that has not heard of a removal then makes an unknowing fork (issues/outside-fire-fork-window.md).
- Open, same field: a writer holding no secret of the thing (a keyless grant) can copy an earlier epoch's keyset back into `keys.0`; until the admin's next step reaches the sender, the step naming that epoch is in force again. A writer holding the new epoch could hand the fires on anyway; a keyless one could not.
