//! Carets kept across merges into text sessions (`edit::shown_edits`, `edit::map_byte`).
use osis_kit::edit::{map_byte, shown_edits};
use osis::Splice;

/// A caret kept across a remote merge: through the reported edits when they lead from the shown
/// text to the session's, else through one diffed splice; byte indices, multi-byte chars.
#[test]
fn caret_maps_through_remote_edits() {
    let shown = "héllo wörld";
    let text = "Héllo big wörld";
    let sp = |at, del, text: &str| Splice { at, del, text: text.into() };
    let reported = vec![sp(0, 1, "H"), sp(6, 0, "big ")];
    let caret = shown.find('r').unwrap();
    let e = shown_edits(shown, reported.clone(), text);
    assert_eq!(e, reported, "the reported edits lead there");
    assert_eq!(map_byte(shown, &e, text, caret), text.find('r').unwrap());
    assert_eq!(map_byte(shown, &e, text, shown.len()), text.len(), "the end stays the end");
    // stale reports (typing raced the merge): one splice from a diff still keeps a caret
    // outside the change
    let e = shown_edits(shown, vec![sp(0, 1, "X")], text);
    assert_eq!(e.len(), 1);
    assert_eq!(map_byte(shown, &e, text, caret), text.find('r').unwrap());
}
