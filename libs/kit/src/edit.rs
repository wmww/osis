//! Carets across merges: `shown_edits` gives the edits a merge makes to what a widget shows,
//! `map_byte` moves a caret or selection end through them.

use osis::Splice;

/// `o -> n` as one splice: (start, chars removed, chars inserted), common prefix and suffix
/// kept.
fn diff(o: &[char], n: &[char]) -> (usize, usize, Vec<char>) {
    let pre = o.iter().zip(n).take_while(|(a, b)| a == b).count();
    let suf = o.iter().rev().zip(n.iter().rev()).take(o.len().min(n.len()) - pre).take_while(|(a, b)| a == b).count();
    (pre, o.len() - suf - pre, n.get(pre..n.len() - suf).unwrap_or_default().to_vec())
}

/// The edits from `shown` (the widget's text) to `text` (the session's), to map the caret
/// through: the edits the session reported since `shown` when they lead there, else one splice
/// (typing raced the merge, or a merge landed after the report was taken).
pub fn shown_edits(shown: &str, reported: Vec<Splice>, text: &str) -> Vec<Splice> {
    let mut t: Vec<char> = shown.chars().collect();
    for e in &reported {
        if e.at + e.del > t.len() {
            break;
        }
        t.splice(e.at..e.at + e.del, e.text.chars());
    }
    if t.iter().copied().eq(text.chars()) {
        return reported;
    }
    let (at, del, ins) = diff(&shown.chars().collect::<Vec<_>>(), &text.chars().collect::<Vec<_>>());
    vec![Splice { at, del, text: ins.into_iter().collect() }]
}

/// Byte index `b` of `shown` mapped through `edits` to a byte index of `text` (what they lead
/// to): a caret or selection end kept across a merge.
pub fn map_byte(shown: &str, edits: &[Splice], text: &str, b: usize) -> usize {
    let c = shown.get(..b).map_or(0, |p| p.chars().count());
    let c = edits.iter().fold(c, |c, e| e.map(c));
    text.char_indices().nth(c).map_or(text.len(), |(i, _)| i)
}
