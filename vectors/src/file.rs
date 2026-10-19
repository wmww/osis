//! The `.vec` text format: records of `key: value` lines separated by blank lines, `#` comments.
//! The first record is the header (`subject`, `spec`, `source`); each later one is a case.

use std::collections::BTreeSet;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Record {
    pub fields: Vec<(String, String)>,
}

impl Record {
    pub fn new() -> Record {
        Record::default()
    }
    pub fn with(mut self, k: &str, v: impl Into<String>) -> Record {
        self.fields.push((k.to_string(), v.into()));
        self
    }
    pub fn get(&self, k: &str) -> Option<&str> {
        self.fields.iter().find(|(key, _)| key == k).map(|(_, v)| v.as_str())
    }
    pub fn req(&self, k: &str) -> Result<&str, String> {
        self.get(k).ok_or_else(|| format!("{}: missing field {k}", self.name()))
    }
    pub fn name(&self) -> &str {
        self.get("case").unwrap_or("<header>")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VecFile {
    pub header: Record,
    pub cases: Vec<Record>,
}

impl VecFile {
    pub fn parse(text: &str) -> Result<VecFile, String> {
        let mut records = Vec::new();
        let mut cur = Record::new();
        for (n, line) in text.lines().enumerate() {
            if line.starts_with('#') {
                continue;
            }
            if line.trim().is_empty() {
                if !cur.fields.is_empty() {
                    records.push(std::mem::take(&mut cur));
                }
                continue;
            }
            let (k, v) = line.split_once(": ").ok_or_else(|| format!("line {}: expected `key: value`", n + 1))?;
            if cur.get(k).is_some() {
                return Err(format!("line {}: duplicate field {k}", n + 1));
            }
            cur.fields.push((k.to_string(), v.to_string()));
        }
        if !cur.fields.is_empty() {
            records.push(cur);
        }
        let mut it = records.into_iter();
        let header = it.next().ok_or("empty file")?;
        header.req("subject")?;
        let cases: Vec<Record> = it.collect();
        let mut names = BTreeSet::new();
        for c in &cases {
            let name = c.req("case")?;
            if !names.insert(name) {
                return Err(format!("duplicate case {name}"));
            }
            c.req("spec")?;
        }
        Ok(VecFile { header, cases })
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        for (i, r) in std::iter::once(&self.header).chain(&self.cases).enumerate() {
            if i > 0 {
                out.push('\n');
            }
            for (k, v) in &r.fields {
                out.push_str(&format!("{k}: {v}\n"));
            }
        }
        out
    }

    /// Cases to run: those without a `pending` field.
    pub fn live(&self) -> impl Iterator<Item = &Record> {
        self.cases.iter().filter(|c| c.get("pending").is_none())
    }
}
