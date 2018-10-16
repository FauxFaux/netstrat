mod client;
mod diag;
pub mod tcp;

#[cfg(target_env = "musl")]
mod netlink_musl;
#[cfg(target_env = "musl")]
use self::netlink_musl as netlink_consts;

#[cfg(not(target_env = "musl"))]
mod netlink_libc;
#[cfg(not(target_env = "musl"))]
use self::netlink_libc as netlink_consts;

pub use self::client::NetlinkDiag;
pub use self::diag::InetDiag;
