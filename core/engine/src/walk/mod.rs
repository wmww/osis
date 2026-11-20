//! The walk along stated paths (`osis_perm::paths`, notes/perm-paths.md), engine side: what the
//! switch from today's walk needs, built while today's walk still decides (notes/perm-paths.md,
//! The switch). `input` adapts held commits to the walk's input, one definition for every way a
//! commit comes or goes; `classes` names the designed differences between the two walks; debug
//! builds keep a shadow walk beside today's and compare them (`shadow`). Nothing here moves a
//! verdict.

pub mod classes;
pub mod input;
#[cfg(debug_assertions)]
pub(crate) mod shadow;
pub mod store;
pub mod verdict;
#[cfg(test)]
mod tests;
