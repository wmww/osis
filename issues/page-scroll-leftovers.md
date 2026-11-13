# Page scroll leftovers
> Summary: Small gaps in the one-scroller page (libs/kit/src/widgets/page.rs): each scroll re-measures the page and lays the loaded rows out a second time (bounded by the window, but doubled work); the status line and screen edges sit outside the page, so below ~50 px nothing shows (the status line could be a page part); the list's bar is drawn over the whole page but can be grabbed only where it overlaps the list; no direct test that a field taking focus scrolls into view.
> Priority: low
> Tags: app
