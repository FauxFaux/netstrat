use std::fmt;
use std::net::IpAddr;

mod nom_util;
mod parse;
use netlink::tcp::States;
use netlink::InetDiag;
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
    EitherAddr,
    SrcPort,
    DstPort,
    EitherPort,
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

    fn apply_addr(&self, left: IpAddr, left_port: u16, right: AddrMaskPort) -> bool {
        use self::Op::*;
        match *self {
            Eq => {
                right.matches_addr(left)
                    && (right.port.is_none() || left_port == right.port.unwrap())
            }
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

    fn matches_addr(self, msg: IpAddr) -> bool {
        let filter = self.addr.expect("filter bug: address absent");

        let mask = match self.mask {
            Some(mask) => mask,
            None => return filter == msg,
        };

        match filter {
            IpAddr::V4(filter) => {
                if let IpAddr::V4(msg) = msg {
                    let mask: u32 = !((1 << (32 - mask)) - 1);
                    u32::from(msg) & mask == u32::from(filter) & mask
                } else {
                    false
                }
            }
            IpAddr::V6(_filter) => {
                if let IpAddr::V6(_msg) = msg {
                    unimplemented!("v6 with mask")
                } else {
                    false
                }
            }
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

        let op = self.op;
        let msg_sport = addr.msg.src_port();
        let msg_dport = addr.msg.dst_port();
        let filter_port = self.addr.port.unwrap_or(0);

        match self.input {
            SrcPort => op.apply_u16(msg_sport, filter_port),
            DstPort => op.apply_u16(msg_dport, filter_port),
            EitherPort => {
                op.apply_u16(msg_dport, filter_port) || op.apply_u16(msg_sport, filter_port)
            }
            Src => addr
                .msg
                .src_addr()
                .map(|addr| op.apply_addr(addr, msg_sport, self.addr))
                .unwrap_or(false),
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
    pub fn matches(&self, addr: &InetDiag, pid_map: Option<&PidMap>) -> bool {
        use self::Expression::*;
        match *self {
            Addr(filter) => filter.matches(addr),
            State(filter) => filter.matches(addr),
            AllOf(ref list) => list.iter().all(|x| x.matches(addr, pid_map)),
            AnyOf(ref list) => list.iter().any(|x| x.matches(addr, pid_map)),
            Not(ref expr) => !expr.matches(addr, pid_map),
        }
    }

    pub fn simplify(self) -> Expression {
        use self::Expression::*;
        let run = match self {
            AllOf(list) => AllOf(simplify_list(list)),
            AnyOf(list) => AnyOf(simplify_list(list)),
            Not(item) => Not(Box::new(item.simplify())),
            other => other,
        };

        let run = match run {
            AllOf(list) => {
                if 1 == list.len() {
                    list.into_iter().next().unwrap()
                } else {
                    AllOf(list)
                }
            }
            AnyOf(list) => {
                if 1 == list.len() {
                    list.into_iter().next().unwrap()
                } else {
                    AnyOf(list)
                }
            }
            other => other,
        };

        run
    }
}

fn simplify_list(list: Vec<Expression>) -> Vec<Expression> {
    list.into_iter().map(Expression::simplify).collect()
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
    let mut it = list.iter();
    write!(f, "({:?}", it.next().unwrap())?;

    for expr in it {
        write!(f, "{}{:?}", delim, expr)?;
    }

    write!(f, ")")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn mask_eq() {
        use super::AddrMaskPort;

        let amp = AddrMaskPort::new_str_v4(Some("192.168.44.7"), None, None);
        assert!(amp.matches_addr("192.168.44.7".parse().unwrap()));
        assert!(!amp.matches_addr("192.168.4.7".parse().unwrap()));

        let amp = AddrMaskPort::new_str_v4(Some("192.168.32.0"), Some(24), None);
        assert!(amp.matches_addr("192.168.32.4".parse().unwrap()));
        assert!(!amp.matches_addr("192.168.3.4".parse().unwrap()));

        let amp = AddrMaskPort::new_str_v4(Some("192.168.32.0"), Some(32), None);
        assert!(amp.matches_addr("192.168.32.0".parse().unwrap()));
        assert!(!amp.matches_addr("192.168.32.1".parse().unwrap()));
    }
}
