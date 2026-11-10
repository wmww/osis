# Thing templates in schemas
> Summary: Proposal only, not for implementation until Tess gives the go-ahead: a schema may declare templates, named bundles of initial writes (aspects, values, settings such as a thing's history setting); creating a thing from a template makes those writes in its creating commit. Write-side convenience only: nothing on the wire, things stay kindless sets of aspects that can gain or lose any aspect later.
> Priority: low
> Tags: tess-call, schema, api

## Proposal
- Things have no kind (ECS entities, not classes), so per-thing properties that a schema would like to suggest (a history setting, an expiry, starting values) have nowhere to come from except the writes that create the thing.
- A template is declared in a schema: a name and the aspects with initial values it writes. `create from template` makes exactly those writes, in the creating commit, plus whatever else the caller writes.
- Nothing records the template: no type tag, no wire bytes, no validity rule. A node without the schema sees ordinary writes. Adding or removing aspects later is unaffected.
- Generated typed API: one constructor per template (notes/api-design.md applies).

## Open
- Parameters (a template needing caller values) or fixed values only.
- Composition (one template including another) or flat.
- Whether the app and kit would use templates for their own things (chat, contacts, notes) or keep writing directly.
