use std::fmt;
use std::net::IpAddr;

mod nom_util;
mod parse;
use netlink::InetDiag;
use netlink::tcp::States;
use pid_map::PidMap;

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
#[derive(Copy, Clone, Default, Eq, PartialEq)]
pub struct AddrMaskPort {
    addr: Option<IpAddr>,
    mask: Option<u8>,
    port: Option<u16>,
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct AddrFilter {
    input: Input,
    op: Op,
    addr: AddrMaskPort,
}

#[derive(Clone, Eq, PartialEq)]
pub enum Expression {
    Addr(AddrFilter),
    State(States),
    AllOf(Vec<Expression>),
    AnyOf(Vec<Expression>),
    Not(Box<Expression>),
}

impl Op {
    fn apply_u16(&self, left: u16, right: u16) -> bool {
        use self::Op::*;
        match *self {
            Eq => left == right,
            other => unimplemented!("op: {:?}", other),
        }
    }
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

impl fmt::Debug for AddrMaskPort {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(addr) = self.addr {
            match addr {
                IpAddr::V4(addr) => write!(f, "[{:?}]", addr)?,
                IpAddr::V6(addr) => write!(f, "[{:?}]", addr)?,
            }
            if let Some(mask) = self.mask {
                write!(f, "/{}", mask)?;
            }
        } else {
            assert!(self.mask.is_none(), "mask without address is invalid");
        }

        if let Some(port) = self.port {
            write!(f, ":{}", port)?;
        }

        Ok(())
    }
}

impl AddrFilter {
    fn matches(&self, addr: &InetDiag) -> bool {
        use self::Input::*;
        let u16f = |l, r| self.op.apply_u16(l, r);
        match self.input {
            SrcPort => u16f(addr.msg.src_port(), self.addr.port.unwrap_or(0)),
            DstPort => u16f(addr.msg.dst_port(), self.addr.port.unwrap_or(0)),
            other => unimplemented!("input: {:?}", other),
        }
    }
}

impl fmt::Debug for AddrFilter {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?} {:?} {:?}", self.input, self.op, self.addr)
    }
}

impl Expression {
    pub fn matches(&self, addr: &InetDiag, pid_map: &PidMap) -> bool {
        use self::Expression::*;
        match *self {
            Addr(filter) => filter.matches(addr),
            AllOf(ref list) => list.iter().all(|x| x.matches(addr, pid_map)),
            AnyOf(ref list) => list.iter().any(|x| x.matches(addr, pid_map)),
            ref other => unimplemented!("expression: {:?}", other),
        }
    }
}

impl fmt::Debug for Expression {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Expression::*;
        match *self {
            Addr(filter) => write!(f, "({:?})", filter),
            // TODO: "state A or state B" this?
            State(filter) => write!(f, "({:?})", filter),
            AllOf(ref list) => write_list(f, list, " and "),
            AnyOf(ref list) => write_list(f, list, " or "),
            Not(ref expr) => write!(f, "not {:?}", expr),
        }
    }
}

fn write_list(f: &mut fmt::Formatter, list: &[Expression], delim: &str) -> fmt::Result {
    if 1 == list.len() {
        return write!(f, "{:?}", list[0]);
    }

    let mut it = list.iter();
    write!(f, "({:?}", it.next().unwrap())?;

    for expr in it {
        write!(f, "{}{:?}", delim, expr)?;
    }

    write!(f, ")")?;

    Ok(())
}
