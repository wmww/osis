//! Lexer for `*.osis` files (notes/data-model.md, Schema DSL).

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Tok {
    Ident(String),
    Int(u64),
    Float(f64),
    Str(String),
    /// `0x...`, even number of hex digits.
    Hex(Vec<u8>),
    /// `/a/b`: an AK or signal kind.
    Ak(String),
    /// `30d`, `12h`, `5m`, `10s`, `250ms`: milliseconds.
    Dur(u64),
    Punct(char),
    /// `///` line, attached to the next item.
    Doc(String),
    /// `//!` line, the schema's doc.
    InnerDoc(String),
    Eof,
}

#[derive(Clone, Debug)]
pub(crate) struct Token {
    pub tok: Tok,
    pub line: u32,
    pub col: u32,
}

pub(crate) struct LexError {
    pub line: u32,
    pub col: u32,
    pub msg: String,
}

struct Lexer<'a> {
    chars: std::iter::Peekable<std::str::Chars<'a>>,
    line: u32,
    col: u32,
}

impl Lexer<'_> {
    fn peek(&mut self) -> Option<char> {
        self.chars.peek().copied()
    }
    fn bump(&mut self) -> Option<char> {
        let c = self.chars.next()?;
        if c == '\n' {
            self.line += 1;
            self.col = 1;
        } else {
            self.col += 1;
        }
        Some(c)
    }
    fn take_while(&mut self, f: impl Fn(char) -> bool) -> String {
        let mut s = String::new();
        while let Some(c) = self.peek().filter(|c| f(*c)) {
            s.push(c);
            self.bump();
        }
        s
    }
}

pub(crate) fn lex(src: &str) -> Result<Vec<Token>, LexError> {
    let mut lx = Lexer { chars: src.chars().peekable(), line: 1, col: 1 };
    let mut out = Vec::new();
    loop {
        let (line, col) = (lx.line, lx.col);
        let err = |msg: &str| LexError { line, col, msg: msg.to_string() };
        let Some(c) = lx.peek() else {
            out.push(Token { tok: Tok::Eof, line, col });
            return Ok(out);
        };
        let tok = if c.is_whitespace() {
            lx.bump();
            continue;
        } else if c == '/' {
            lx.bump();
            if lx.peek() == Some('/') {
                lx.bump();
                let kind = lx.peek();
                let text = lx.take_while(|c| c != '\n');
                let body = |t: &str| t.get(1..).unwrap_or("").strip_prefix(' ').unwrap_or(t.get(1..).unwrap_or("")).to_string();
                match kind {
                    Some('/') if !text.starts_with("//") => Tok::Doc(body(&text)),
                    Some('!') => Tok::InnerDoc(body(&text)),
                    _ => continue,
                }
            } else {
                let rest = lx.take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '@' | '/'));
                Tok::Ak(format!("/{rest}"))
            }
        } else if c.is_ascii_digit() {
            let digits = lx.take_while(|c| c.is_ascii_alphanumeric() || c == '_');
            if let Some(hex) = digits.strip_prefix("0x") {
                let hex: String = hex.chars().filter(|c| *c != '_').collect();
                if !hex.len().is_multiple_of(2) || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err(err("hex literal needs an even number of hex digits"));
                }
                let bytes = (0..hex.len() / 2)
                    .map(|i| hex.get(2 * i..2 * i + 2).and_then(|b| u8::from_str_radix(b, 16).ok()))
                    .collect::<Option<Vec<u8>>>()
                    .ok_or_else(|| err("bad hex literal"))?;
                Tok::Hex(bytes)
            } else if lx.peek() == Some('.') && digits.chars().all(|c| c.is_ascii_digit()) {
                lx.bump();
                let frac = lx.take_while(|c| c.is_ascii_digit());
                let mut s = format!("{digits}.{frac}");
                if matches!(lx.peek(), Some('e' | 'E')) {
                    s.push('e');
                    lx.bump();
                    if let Some(sign) = lx.peek().filter(|c| matches!(c, '+' | '-')) {
                        s.push(sign);
                        lx.bump();
                    }
                    s.push_str(&lx.take_while(|c| c.is_ascii_digit()));
                }
                Tok::Float(s.parse().map_err(|_| err("bad float literal"))?)
            } else {
                let split = digits.find(|c: char| !c.is_ascii_digit()).unwrap_or(digits.len());
                let (num, unit) = digits.split_at(split);
                let n: u64 = num.parse().map_err(|_| err("integer literal out of range"))?;
                let mult = match unit {
                    "" => None,
                    "ms" => Some(1),
                    "s" => Some(1000),
                    "m" => Some(60_000),
                    "h" => Some(3_600_000),
                    "d" => Some(86_400_000),
                    _ => return Err(err("unknown duration unit (ms, s, m, h, d)")),
                };
                match mult {
                    None => Tok::Int(n),
                    Some(m) => Tok::Dur(n.checked_mul(m).ok_or_else(|| err("duration out of range"))?),
                }
            }
        } else if c.is_ascii_alphabetic() || c == '_' {
            Tok::Ident(lx.take_while(|c| c.is_ascii_alphanumeric() || c == '_'))
        } else if c == '"' {
            lx.bump();
            let mut s = String::new();
            loop {
                match lx.bump() {
                    None | Some('\n') => return Err(err("unterminated string")),
                    Some('"') => break,
                    Some('\\') => match lx.bump() {
                        Some('n') => s.push('\n'),
                        Some('t') => s.push('\t'),
                        Some('"') => s.push('"'),
                        Some('\\') => s.push('\\'),
                        _ => return Err(err("unknown escape (\\n \\t \\\" \\\\)")),
                    },
                    Some(ch) => s.push(ch),
                }
            }
            Tok::Str(s)
        } else if "{}()<>[];:,=-".contains(c) {
            lx.bump();
            Tok::Punct(c)
        } else {
            return Err(err(&format!("unexpected character {c:?}")));
        };
        out.push(Token { tok, line, col });
    }
}
