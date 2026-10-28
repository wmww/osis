//! Lower-case hex for text forms (schema locks, vectors) and test constants.

/// Lower-case hex of `b`.
pub fn encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Bytes of hex text, ASCII whitespace ignored; `None` on an odd digit count or a non-hex
/// character.
pub fn decode(s: &str) -> Option<Vec<u8>> {
    let digits: Vec<u32> = s.bytes().filter(|c| !c.is_ascii_whitespace()).map(|c| char::from(c).to_digit(16)).collect::<Option<_>>()?;
    if !digits.len().is_multiple_of(2) {
        return None;
    }
    digits
        .chunks(2)
        .map(|p| match p {
            [h, l] => u8::try_from(h * 16 + l).ok(),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    // spec: none (text helper)
    #[test]
    fn hex_round_trip() {
        assert_eq!(super::encode(&[0, 0xab, 0x7f]), "00ab7f");
        assert_eq!(super::decode("00 AB\n7f"), Some(vec![0, 0xab, 0x7f]));
        assert_eq!(super::decode("abc"), None);
        assert_eq!(super::decode("zz"), None);
    }
}
