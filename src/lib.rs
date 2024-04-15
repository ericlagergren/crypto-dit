//! Data independent timing (DIT) support.
//!
//! # CPU Support
//!
//! This crate currently only supports AArch64's [DIT].
//!
//! This module is a no-op on non-AArch64 architectures, AArch64
//! CPUs without `FEAT_DIT` support, or when the `dit` feature is
//! disabled.
//!
//! # Async Support
//!
//! DIT is only enabled for the current thread, so it may not
//! persist across await points.
//!
//! [DIT]: https://developer.arm.com/documentation/ddi0601/latest/AArch64-Registers/DIT--Data-Independent-Timing

#![cfg_attr(docs, feature(doc_cfg))]
#![cfg_attr(not(any(feature = "std", test)), no_std)]
#![deny(
    clippy::alloc_instead_of_core,
    clippy::cast_lossless,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::expect_used,
    clippy::implicit_saturating_sub,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::panic,
    clippy::ptr_as_ptr,
    clippy::std_instead_of_core,
    clippy::string_slice,
    clippy::transmute_ptr_to_ptr,
    clippy::undocumented_unsafe_blocks,
    clippy::unimplemented,
    clippy::unwrap_used,
    clippy::wildcard_imports,
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]

mod dit;

pub use dit::*;
