# An admin that has not heard of a removal can let the removed reader read outside fires
> Summary: An admin that has not yet received a writer's removal of reader R may rotate read (boxing R) and step; an outsider holding both keysets then seals its fires to the admin's epoch, which R reads, until the admin hears of the removal and rotates again.
> Priority: low
> Tags: security, sync, keys, tess-call

- What happens: writer W removes R and rotates read (epoch e3). Admin A has not received it, rotates read itself (e5, boxing R: it does not know R left) and steps. `keys.0` keeps one read keyset, and A's e5 is stamped later, so it wins. An outsider O that holds both e3 and e5 seals to e5, A's read key. R reads those fires until A receives e3; A then rotates (e5 does not cover a departure it knows) and steps, and O seals to the new epoch.
- Same window as content: spec/requirements.md Permissions says a removed holder stops reading "once a party with the right to change the keys has done so knowing of the removal and a writer has written since", and spec/crypto.md §4 (Encrypting under) lets a node that has not heard of a departure write under its own fork. So A's own writes in this window are readable by R too, and that is accepted. The window lasts exactly as long here.
- Difference: a holder writing content that holds both e3 and e5 sees e5 does not cover R's departure and rotates first. O holds `keys.0` alone, cannot judge coverage, and sees only the later keyset. So O, which already holds the knowing rotation, still seals to an epoch R reads.
- Trade-off: closing it needs `keys.0` to keep every current read keyset (not one), the read key to vouch for all of them, and O to seal only when the read key covers every current keyset it holds. That is a larger `keys.0`, a set-valued field and more pending fires during every fork, to shorten a window the requirement already allows for content.
- Question for Tess: is the content window acceptable for outside fires too (keep as is), or should an outside sender that holds the knowing rotation never seal to an unknowing fork (pay the cost above)?
- Model: core/test/tla/rotation/FireKey.tla F2 (`FK_fork`).
