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

bitflags! {
    pub struct State: u16 {
        const ESTABLISHED  = (1 << 1);
        const SYN_SENT     = (1 << 2);
        const SYN_RECV     = (1 << 3);
        const FIN_WAIT_1   = (1 << 4);
        const FIN_WAIT_2   = (1 << 5);
        const TIME_CLOSE   = (1 << 6);
        const CLOSE        = (1 << 7);
        const CLOSE_WAIT   = (1 << 8);
        const LAST_ACK     = (1 << 9);
        const LISTEN       = (1 << 10);
        const CLOSING      = (1 << 11);
        const NEW_SYN_RECV = (1 << 12);
    }
}

impl State {
    fn connected() -> State {
        State::ESTABLISHED | State::SYN_SENT | State::SYN_RECV | State::FIN_WAIT_1
            | State::FIN_WAIT_2 | State::CLOSE_WAIT | State::LAST_ACK | State::CLOSING
    }
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
    State(State),
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
