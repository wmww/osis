# deep-pages
> Summary: slow spots met making held-writes pages split at any depth.

- `paged_rows_read_as_plain_rows` used values of one repeated byte, which `pack` shrinks to nothing: no page grew past its bound, so the split paths were never reached. A paging test needs incompressible values.
