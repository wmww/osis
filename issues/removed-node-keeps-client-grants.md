# A removed node keeps acting for the account through things it alone administers
> Summary: `Osis::add_client` mints a client's actor with the node thing N as its admin; once that actor (or any thing minted with admin N) holds a role in the account, removing N (osis-account `remove_node`: N's grant on A alone) leaves N writing through it, e.g. along [C, A].
> Priority: normal
> Tags: security, account, osis

Property: a removed device stops acting for the account (spec/permissions.md §8 Removing; notes/realms.md).

Minimal world: node N1 of account A registers client C (`add_client`: C minted with admin N1) and grants C write on A, or on a realm thing of A. Node N2 removes N1. N1 is still C's admin, so its commits signed as N1 stating [C, A] are valid; `holders(A)` shows C. Unverified: whether `set_role` refuses the removal at the "reaches A through C" arm.

Options:
1. Clients of a node acting for an account are minted with admin A (the account administers them; every node of A then may end them).
2. `remove_node` also removes the roles held in the account by things only N administers (or refuses, naming them).
3. Accept: the account's admins see C among A's holders and remove it by hand (the library says so in `remove_node`'s result, as it returns the links still working).
