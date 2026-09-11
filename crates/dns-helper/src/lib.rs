//! Privileged DNS helper internals, exposed as a library so the safety-critical
//! paths (resolv.conf takeover, proxy routing) can be integration tested.

pub mod diagnose;
pub mod dpi;
pub mod dpi_proxy;
pub mod filter_route;
pub mod proxy;
pub mod resolvconf;
pub mod status;
pub mod apps;
pub mod tunnel;
pub mod upstream;
