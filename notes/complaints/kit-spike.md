# kit-spike
> Summary: footguns met while spiking Vello backgrounds and Parley fonts under Masonry 0.4.

- masonry_winit runs the first layout before `AppDriver::on_start`, so fonts registered there are absent on the first layout pass; anything keyed on a registered family (e.g. a generic-family override) must retry until the family exists (register_fonts requests a relayout, so it does).
- Masonry's default theme paints Label text white; a light test background makes labels look missing until `ContentColor` is set.
