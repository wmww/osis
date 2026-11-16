# keel-make-cost
- `Effects` cause labels name a stamp family only ("store: catalog kind 11", "timelines: whole"), never the key or the reader: finding which read moved took ad-hoc backtrace probes in `Stamps::record` and `Effects::due`. A debug-only "why due" (table, key, reader frame) behind an env var would have saved most of the time.
- The store's table owner stamp was the owning catalog row's own key, so a table handle read (`index(name)`) moved with every row write: invisible from the label, which showed the family only.
- One-make cost tests trip on compaction spikes and on driver-round parity (follows 24/26 alternating); the least of three makes and a "grew past half again" bound were needed.
