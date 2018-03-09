use std::net::IpAddr;

mod nom_util;
mod parse;

pub use self::parse::parse;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Op {
    Eq,
    Ne,
    Gt,
    Lt,
    Ge,
    Le,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Input {
    Src,
    Dst,
    SrcPort,
    DstPort,
    Either,
}

/// At least one of addr or port should probably be set?
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct AddrMaskPort {
    addr: Option<IpAddr>,
    mask: Option<u8>,
    port: Option<u16>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AddrFilter {
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
        use std::net::Ipv4Addr;
        AddrMaskPort {
            addr: addr.map(|addr| addr.parse::<Ipv4Addr>().unwrap().into()),
            mask,
            port,
        }
    }
}
