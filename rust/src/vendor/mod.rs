// SPDX-License-Identifier: MIT

//! Vendored copies of helpers that exist in `libprio-rs` but are not exported
//! across crate boundaries (`pub(crate)` or fully private items).
//!
//! Each submodule documents the upstream source. These exist as a workaround
//! for the Mastic/VIDPF source moving outside of `libprio-rs`; once upstream
//! exposes the necessary API surface (or once we no longer depend on `prio`
//! at all), the vendored helpers should be removed in favor of the upstream
//! versions.
//!
//! Provenance: <https://github.com/divviup/libprio-rs/tree/4e497a290fbd81298ada708135e7957322051f25>.

pub(crate) mod field;
pub(crate) mod idpf;
pub(crate) mod xof;
