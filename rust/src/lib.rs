// SPDX-License-Identifier: MIT

//! Reference implementation of Mastic, a VDAF for the private computation of
//! aggregate statistics over inputs grouped by a private attribute.
//!
//! The Mastic and VIDPF code in this crate was originally part of
//! [`libprio-rs`][libprio-rs] and was extracted at commit `4e497a2` (the last
//! commit before Mastic was removed in PR #1411). The source files are copied
//! verbatim during the initial port; subsequent commits will align them with
//! the latest version of the [Mastic draft][draft] and a newer release of
//! `prio`.
//!
//! [libprio-rs]: https://github.com/divviup/libprio-rs
//! [draft]: https://datatracker.ietf.org/doc/draft-mouris-cfrg-mastic/

// Re-exports of items from `prio` that the copied Mastic/VIDPF source files
// reference as `crate::<name>`. These let the verbatim copy compile without
// rewriting paths. They are an implementation detail and may shrink or
// disappear as the code is updated to depend on `prio` directly.
pub use prio::codec;
pub use prio::field;
pub use prio::flp;
pub use prio::idpf;

// `bt` is a private module in `prio`, so we vendor it locally.
pub(crate) mod bt;

pub mod vdaf;
pub mod vidpf;
