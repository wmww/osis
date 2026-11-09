# A refused purge reports `needs: Write`
> Summary: `commit()` refuses a purge request whose rights drop none of the held deltas it names with the engine's `Permission { tid }`, which carries no role, so osis reports `needs: Write` to a writer that has it. The right needed is admin (`admin`, `author_or_admin` sets) or no role at all (`author` on another's write, `nobody`), which `needs: Role` cannot say.
> Priority: low
> Tags: osis, api

Fix shape: the engine's refusal says which (a role, or none grants it), and osis's error can say "no role" (e.g. its own variant), not a guessed role.
