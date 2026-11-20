# vouch-cost-review
> Summary: footguns met reviewing the vouch trigger narrowing.

- A wake reading `core.ix.commits` for the commit being applied sees nothing in `apply_verified` before `put_meta`: `note_applied` had to move after it to know the receipt.
- The per-judgement debug check (kept gathering == fresh) cannot see a stale gathering with no judgement due; the drop check (`vouches::missed`) does, but no suite world races a removal against a late lowering of another path, so it passed every suite with the hole open; it took a hand-built case.
