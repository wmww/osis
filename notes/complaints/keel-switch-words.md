# keel-switch-words
> Summary: mishaps met fixing the switched node's own-listing carry.

- `tests_custody`'s failure text (`why`) shows only the words naming a commit, one level: the carrier here was two levels down (a listing named by its author's later listing). A throwaway recursive trace of `lists::names_of` with each word's inner node found it in one run; worth having in `why` if this class recurs.
