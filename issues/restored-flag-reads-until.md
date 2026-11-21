# The restored flag reads an until the restored role ignores
> Summary: roles-model `paths` keeps the edge as restored in role with each value's `until` disregarded, but in what it lets its holder grant (`Pass::rgrant`) at the value as alive at its `ts`, so a later lowering drops role-resting writes the may-grant grants beside them escape.
> Priority: normal
> Tags: roles-model

notes/write-path-design.md §1 W3 and G5 judge a lowering against the hop as restored, in role or flag; `Pass::restored` records an explicit write's raw role (`new.0`), `Pass::rgrant` its `grantable(after, flag)` with `after` the value alive at its `ts`. They part for a value already ended at its own `ts`:

- H gives N5 write with the flag at 1; N5 grants Z read by it at 2; H sets N5 write with the flag until 3 at 4, listing Z's grant; H removes N5 at 5 listing nothing. Z's grant stands (`rgrant` None after the write at 4).
- The same with N5's content at 2 in place of the grant: the content falls (`restored` write; perm hand world `an_ended_value_restores_its_role` for the role case).

The fix reads like the role: `rgrant` takes `grantable(new.0, flag)` at an explicit write. With it, G2's "role below admin" is redundant in the model too (`flag_grant`'s bound also decides `need` for held writes not applied, which differs only through this asymmetry) and can go from G2's text and `flag_grant`. A rule change in the model: check the story, `tiny_flags` (`may-grant audited`) and the osis-perm differentials.
