# one-scroller
> Summary: footguns met building the one scroller.

- Masonry caches a widget's layout by constraints: a widget that reports to an ancestor during layout (a page's list) goes silent when laid out from cache, and its mode (measuring or not) cannot ride on constraints. Needed `request_layout_of`; setting `request_layout` there (not just `needs_layout`) looped layout ~60 times per event, silently (tests only got slower).
- Masonry `Flex` with `CrossAxisAlignment::Fill` lays each child out twice, doubling per nesting level: harmless while children cache, 2^depth once a deep child is dirty every frame.
- Text in the accessibility tree lives in `TextRun` child nodes (not widgets): a test looking for a label by widget finds no prose.
- `find_widget_under_pointer` ignores clip paths: a row scrolled under a clip still "hits"; tests must intersect with the clip chain themselves.
- The thing page loses ~50 px to the screen's edges and the status line before the page gets any: tests at "tiny" heights must wheel inside that sliver.
