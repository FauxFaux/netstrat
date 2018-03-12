mod client;
mod diag;
pub mod tcp;

pub use self::client::NetlinkDiag;
pub use self::diag::InetDiag;

pub enum Message {
    InetDiag(InetDiag),
}
