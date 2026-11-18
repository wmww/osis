# Whether a thing has own keys shows to apps and users
> Summary: Tess: whether a thing derives its keys from its first admin or has its own is internal; apps and users see things change admin, get shared and move, and it just works, with promotion implicit. Today the API docs, the CLI help and three behaviours expose it.
> Priority: normal
> Tags: api, cli, perm, engine

The rule (Tess): neither the concept nor its effects reach the `osis` API, its docs, app developers or users.

Where it shows:
- **Docs**: `Write::create` (core/osis/src/write.rs) and `osis create --admin` (cli/src/args.rs) explain plain, own keys and the tenfold cost; `Osis::hold` (core/osis/src/share.rs) says "a thing with own keys". notes/api.md justifies `create` having no default admin by cost.
- **Removing the last admin** of a thing without own keys is refused (`flows::edges::leaves_no_admin`, spec/permissions.md §1); with own keys the same write goes through and leaves it adminless. One rule for both is owed (give it own keys first, or refuse both).
- **A thing made under an account** gets own keys at birth (spec/permissions.md §3, spec/sync-set.md §2), costs ten times one made under the account root, and is in no sync unit unless a ticket carries it. `osis create --admin me` reaches it. An account is a key actor; why nothing may derive from its epochs is not written down. Either make it an ordinary case or keep apps from reaching it.
- **Sharing what a tag holds**: a strong grants nothing, so an app sharing a tag of n things makes n grants itself (issues/many-sync-ids-cost.md). To check whether that counts as the effect showing.

Terms (Tess, tentative, internal only): child thing (derives its keys), parent (first admin), adult thing (own keys). Open: "child" is also a relation, and an adult keeps its parent.
