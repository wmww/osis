# Dependents of a destroyed mint admin stay readable through its secrets
> Summary: A dependent thing D minted with T keeps reading by derivation from T's epochs after T's destruction: every node holding T's secrets (T's holders at the destruction) opens D's content, while no role for keys reaches D through T. Is that "access through it ends" (spec/requirements.md, Purging or expiring a thing's creation), or must nobody read D?
> Priority: normal
> Tags: tess-call, crypto, engine

Built (spar-destroyed-ends): a destroyed T holds no keys (`members::key_skip` skips every grant T holds, its record grant on D included), so nobody holds D for keys through T: nobody rotates D or makes it independent, and D's epochs stay those derived from T's. But D's secrets derive from T's (spec/sync-set.md §2 T's keys open: by derivation, not by role), and T's holders keep T's secrets (their grants on T are not skipped), so `Core::may_read`/`keys_open` say they read D, and their nodes keep its content. Observed in the engine (probe on `destroyed_world`): after T expires every peer reading T, through G too, reads D's value; a write to D fails at T's mint admin (`NotHeld`).

Options:
- **Keep**: D is frozen, read by those holding T's secrets at the destruction; nothing new is written under keys they lack, so nothing leaks past what they held. spec/crypto.md §4 Destroyed states it.
- **Nobody reads a destroyed thing's keys**: `keyed_role_now(x, t)` none for a destroyed t, so every node loses T (lost access) and with it D, and a lost destroyed thing's ways keep no copy. D's content then goes everywhere (a live thing's data lost with its mint admin) unless made independent before.
