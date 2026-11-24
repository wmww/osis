# Actors, signing and forks as one mechanism
> Summary: Tess's direction and answers for accounts as ordinary things (who sees who acted, visible and hidden modes, forks, profiles, identities managed through another) that the design notes (notes/account-membership-design.md, notes/write-path-design.md) do not restate, and what is still open. The build: notes/accounts-switch-brief.md pieces.
> Priority: normal
> Tags: perm, crypto, keys, spec

## Direction (Tess)
- **One nestable rule for who sees who acted**: those inside a thing (holders of some role on it) see which member acted; those outside see the thing acting. The same for nodes in an account, accounts in an org, and any other nesting.
- **Hiding is not welded to the thing acted as**: an account may act through an org and stay visible as itself, or show its node. Showing more must be easy. Sketch (Claude): a commit carries its signatures from the node up, each layer sealed to the next layer's insiders or left clear, the outermost the thing signed as; above it, plain grants. One choice per write: where hiding stops; default the account.
- **Attribution**: the API gives the thing signed as and what it acted through, favouring neither; whose face shows is app policy.
- **Accounts on accounts**: a thing being its own only admin is one arrangement of roles, never a kind of thing or its definition.
- **Forks**: two members removing each other has no right answer inside osis, whatever the members are: both sides go on, others pick a side by a heuristic, warn, and may switch. Never a required merge, never a global winner. With members as things holding roles, account forks are admin disputes and concurrent rotations are key forks that stand (notes/account-membership-design.md §1).
- **Hiding wherever offered pays hiding's cost** (an org's anonymous voice as much as an account's nodes): with a shared key a removal cannot tell members' writes apart, so it vouches for everything (notes/account-membership-design.md §3, §7).

## Answers (Tess)
The rules the design notes state (no eager delivery of removals, nothing vouches for a role write, the last admin a writer's check, the public thing, the purge author as an index into the stated path, core without accounts) are in notes/write-path-design.md (Decided, §1 to §5). Besides them:
- **Visible, hidden kept a design**: two modes over the ordinary rules, visible (each node signs with its own key) and hidden (nodes share a key, hidden from everyone, their own account included); build visible, and keep hidden as a design in its plain form (a shared key with no sealed node signature on any commit) so nothing built rules it out. Hidden's costs against visible: every removal puts every node's writes and grants in question; unsent work falls until its node vouches; honest concurrent swaps dispute; a thief's writes before removal cannot be told from the owner's; no sessions. It is close to the built design (what goes is the parallel layer: chain, epochs, custody, account sides): do not plan on it being simpler. A node pseudonym per thing is acceptable and costs what hidden mode costs (notes/account-membership-design.md §5).
- **A key swap must not read as one person leaving and another joining**: the account stays the identity, its keys are members; the write says so by the thing it is signed as and its stated path.
- **A signing key per node per account**, derived from the node's seed, so a node in two accounts links them for no reader (a node wanting its accounts unlinked uses a thing and signing key for each).
- **Nothing nobody received is kept**: no vouch on a user's say-so; a removed node's unseen writes are untrusted with no exception; a node still in its owner's hands syncs before it is removed. spec/requirements.md keeps "vouches for having received". Role writes of a removed node are kept on the same terms as its content: removing a node from an account must not undo the membership of what was shared from it.
- **Purge author**: chosen at write time, one of the write's own actors; core picks no position on the path. The default is what the session was configured to act as, written by the layer that understands the schema's account, never by core.
- **The account root goes** once the account is an ordinary independent thing; home is the account thing (notes/write-path-design.md §5).
- **Who may make a thing a holder without the external signal**: write on the thing gives the right to grant to it, for a new thing and an existing one alike (admins-only would make minting with it as mint admin, open to writers, a mint-admin special the API would have to explain). A writer can then attach outside things: no new power, and a bounded writer.
- **Profiles: public, and by ordinary sync**: a profile is the schema's, publicly readable; a writer puts a strong reference to its own profile in the thing it writes in, so the profile is in the referrer's sync unit (public is a thing every thing's keys open) and a reader served only by a node keeping that unit unread still fetches it. Nothing in evidence, no `public.0`. Rejected: granting the referring thing read on the profile (the profile's roster would list every thing its owner writes in).
- **Public and contact-only information** (both will have more uses): the dial list leaves the public profile for a thing of its own read by those its owner shares with.

## Identities managed through another (Tess)
Not features to build: a check on the design, each an account thing with some arrangement of member things and signing keys.
- **Unlinked** (name open: persona, alias): an account whose one member is a thing with a shared signing key all the owner's nodes hold; nothing shows the owner's account. It writes with path [P] signed as its member thing.
- **Shared or nested**: the same key also held by another account's nodes; or a member that is itself such an account.
- **Provably linked**: an account whose admin is the owner's account by an ordinary grant; it writes [Owner, P], the chain visible.
- Where privacy counts is often not where edits are many or their history audited, so choosing per identity softens the hidden mode's costs.
- Not part of this design (Tess: well-known problems, mitigated when privacy features are built): the same node serving both identities and both profiles naming the same addresses; every identity a stolen node held swapping keys at once; edits' timing.

## Open
- The nestable hiding rule (Direction): offered generally and paid for where used, or not at all.
- Which mode is the default, and whether the other is opt-in, a toggle, or unexposed to end users.
- A thought, not for building (Tess): a writer minting a dependent of a realm is not its admin, so cannot set its admin-only aspects; perhaps creation carries arbitrary data, admin-only included, which only admins change afterwards; likely the answer is per use (a member makes a sub-realm, grants the main realm a role on it, and mints documents with the sub-realm as admin).
- **The build**: notes/accounts-switch-brief.md (code pieces), notes/redesign-plan.md A5, A6.
