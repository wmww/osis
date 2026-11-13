# Rows past an inner list's window are unreachable
> Summary: A second list on a page, or a list inside a row, lays out whole as its built window (64 rows) and never asks for more, so rows past it cannot be reached on that page and nothing offers to open the list. Wanted: when rows remain, the list ends with an "N more" row that opens its thing (the view supplies the action; the list block does not know the thing), as the calendar's "+N more" does. Cost stays bounded by the window.
> Priority: normal
> Tags: app
