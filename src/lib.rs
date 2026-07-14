//! vaultvert — convert and merge password-manager exports, losslessly.
//!
//! Library layout, one pure module per concern:
//! - [`model`]: the canonical vault/entry model and the spill/lift mechanism
//! - [`bitwarden`], [`onepassword`], [`keepass`]: the format codecs
//! - [`detect`]: format registry, sniffing and dispatch
//! - [`merge`]: duplicate detection and secret-preserving merges
//! - [`report`]: the integrity report and the LOSSLESS verdict
//! - [`json`], [`xml`], [`csv`], [`encode`], [`digest`], [`timefmt`]:
//!   in-tree std-only infrastructure (no dependencies to audit but this crate)

pub mod bitwarden;
pub mod cli;
pub mod csv;
pub mod detect;
pub mod digest;
pub mod encode;
pub mod json;
pub mod keepass;
pub mod merge;
pub mod model;
pub mod onepassword;
pub mod report;
pub mod timefmt;
pub mod xml;
