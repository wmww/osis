//! Typing into text sessions: a widget reports its whole new text; `splice` turns that into one
//! edit of the session, keeping a remote merge the widget does not show yet.

use osis::TextSession;

/// `old -> new` as one splice: (start, chars removed, chars inserted), common prefix and suffix
/// kept. A splice inside a run of equal chars (`aa -> aaa`) can sit anywhere in it: `left` takes
/// the leftmost place, else the rightmost.
fn diff(o: &[char], n: &[char], left: bool) -> (usize, usize, Vec<char>) {
    let common = |a: &mut dyn Iterator<Item = (&char, &char)>| a.take_while(|(a, b)| a == b).count();
    let min = o.len().min(n.len());
    let (pre, suf) = if left {
        let suf = common(&mut o.iter().rev().zip(n.iter().rev()));
        (common(&mut o.iter().zip(n).take(min - suf)), suf)
    } else {
        let pre = common(&mut o.iter().zip(n));
        (pre, common(&mut o.iter().rev().zip(n.iter().rev()).take(min - pre)))
    };
    (pre, o.len() - suf - pre, n.get(pre..n.len() - suf).unwrap_or_default().to_vec())
}

/// Writes the user's change `shown -> new` of a widget into its session as one splice (char
/// indices). A remote change merged into the session but not shown yet is kept: the splice goes
/// before or after it (each placed so they are disjoint if any placement is), or, overlapping it,
/// becomes an insert at its end (the pending `Remote` then shows both).
/// Works around issues/text-session-app-gaps.md.
pub fn splice(s: &TextSession, shown: &str, new: &str) -> osis::Result<()> {
    let sh: Vec<char> = shown.chars().collect();
    let nw: Vec<char> = new.chars().collect();
    if sh == nw {
        return Ok(());
    }
    let rm: Vec<char> = s.text().chars().collect();
    let ((la, ld, li), (ra, _, _)) = (diff(&sh, &nw, true), diff(&sh, &rm, false));
    let (at, del, ins) = if la + ld <= ra {
        (la, ld, li)
    } else {
        let ((la, ld, li), (ra, rd, ri)) = (diff(&sh, &nw, false), diff(&sh, &rm, true));
        if la >= ra + rd {
            (la - rd + ri.len(), ld, li)
        } else {
            let (ra, _, ri) = diff(&sh, &rm, false);
            (ra + ri.len(), 0, li)
        }
    };
    s.replace(at..at + del, &ins.iter().collect::<String>())
}
