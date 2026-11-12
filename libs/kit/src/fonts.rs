//! The theme fonts kit ships (assets/fonts/<family>/{font.ttf, OFL.txt}; notes/theming.md: every
//! font but the platform's own is OFL). Families are named as `text::family` asks for them.

use masonry::peniko::Blob;
use masonry::app::RenderRoot;
use std::sync::Arc;

/// (family name, variable font file).
pub const BUNDLED: [(&str, &[u8]); 8] = [
    ("Inter", include_bytes!("../assets/fonts/inter/font.ttf")),
    ("DM Sans", include_bytes!("../assets/fonts/dmsans/font.ttf")),
    ("Figtree", include_bytes!("../assets/fonts/figtree/font.ttf")),
    ("Lexend", include_bytes!("../assets/fonts/lexend/font.ttf")),
    ("Atkinson Hyperlegible Next", include_bytes!("../assets/fonts/atkinsonhyperlegiblenext/font.ttf")),
    ("Nunito", include_bytes!("../assets/fonts/nunito/font.ttf")),
    ("Literata", include_bytes!("../assets/fonts/literata/font.ttf")),
    ("JetBrains Mono", include_bytes!("../assets/fonts/jetbrainsmono/font.ttf")),
];

/// Registers the bundled fonts with a window (it asks for a relayout, so text laid out before it
/// is redone).
pub fn register(root: &mut RenderRoot) {
    for (_, bytes) in BUNDLED {
        root.register_fonts(Blob::new(Arc::new(bytes)));
    }
}
