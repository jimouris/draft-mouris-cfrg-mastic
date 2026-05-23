// SPDX-License-Identifier: MIT

//! VDAF module.
//!
//! Re-exports `prio::vdaf::*` so that the verbatim Mastic source can refer to
//! items such as `crate::vdaf::xof`, `crate::vdaf::poplar1`,
//! `crate::vdaf::Aggregator`, etc., exactly as it did inside `libprio-rs`.

pub use prio::vdaf::*;

pub mod mastic;
