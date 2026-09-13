//! WinSleuth: Windows instability diagnosis.
//!
//! The crate is split into four layers: `providers` gather raw system state,
//! `core` normalises and scores it, `analysis` holds the heuristics, and
//! `ui_layer` renders the result.

pub mod modules;

pub use modules::core::models;
