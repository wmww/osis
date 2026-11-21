# The spec contradicts itself on the retention setting's aspect class
> Summary: spec/data-model.md §9 lists `retention^.0` (a thing's retention setting) among fixed-retention aspects, while spec/commits.md §5 gives it ordinary retention; the code follows commits.md. Decide by the model which is right (can a thing's history-keeping setting be purged by writers like ordinary content, or is it role-class?) and fix the other.
> Priority: low
> Tags: spec, retention

Found by mizzen-purge-by (the purge-by rename).
