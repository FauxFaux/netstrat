use std::net::IpAddr;
use std::net::Ipv4Addr;

mod nom_util;
mod parse;

pub use self::parse::parse;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum Op {
    Lt,
    Eq,
    Gt,
    Ne,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum Input {
    Src,
    Dst,
    Either,
}

/// At least one of addr or port should probably be set?
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
struct AddrMaskPort {
    addr: Option<IpAddr>,
    mask: Option<u8>,
    port: Option<u16>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct AddrFilter {
    input: Input,
    op: Op,
    addr: AddrMaskPort,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Expression {
    Addr(AddrFilter),
    And(Vec<Expression>),
    Or(Vec<Expression>),
    Not(Box<Expression>),
}

impl AddrMaskPort {
    #[cfg(test)]
    fn new_str_v4(addr: Option<&str>, mask: Option<u8>, port: Option<u16>) -> AddrMaskPort {
        AddrMaskPort {
            addr: addr.map(|addr| addr.parse::<Ipv4Addr>().unwrap().into()),
            mask,
            port,
        }
    }
}
