//! Core DNS logic shared by the privileged helper and the Tauri front end.
//!
//! Deliberately free of any privileged or platform-specific code so it can be
//! unit tested without root.

pub mod cache;
pub mod config;
pub mod policy;
pub mod provider;
pub mod resolver;

pub use config::{AppProfile, Config, TunnelApp};
pub use policy::{Policy, Route};
pub use provider::{default_providers, Provider};
pub use resolver::{DohResolver, ResolveError};
