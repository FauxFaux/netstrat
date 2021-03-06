use std::mem;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

use cast::i32;
use failure::Error;
use libc::c_int;
use libc::c_short;
use libc::AF_INET;
use libc::AF_INET6;
use nix::sys::socket::AddressFamily;

use netlink::tcp::State;
use netlink::tcp::TcpInfo;

#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct InetDiagReqV2 {
    pub family: u8,
    pub protocol: u8,
    pub ext: u8,
    pub _pad: u8,
    pub states: u32,
    pub id: InetDiagSockId,
}

#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct InetDiagSockId {
    sport_be: u16,
    dport_be: u16,
    src_be: [u32; 4],
    dst_be: [u32; 4],
    pub iface: u32,
    pub cookie: [u32; 2],
}

#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct InetDiagMsg {
    pub family: u8,
    pub state: u8,
    pub timer: u8,
    pub retrans: u8,
    pub id: InetDiagSockId,
    pub expires: u32,
    pub rqueue: u32,
    pub wqueue: u32,
    pub uid: u32,
    pub inode: u32,
}

#[derive(Copy, Clone, Default, Debug)]
pub struct InetDiag {
    pub msg: InetDiagMsg,
    pub tcp: Option<TcpInfo>,
}

#[derive(Copy, Clone, Debug)]
#[repr(i16)]
#[allow(dead_code)]
pub enum RtaMessageType {
    None,
    MemInfo,
    Info,
    VegasInfo,
    Cong,
    ToS,
    TClass,
    SkMemInfo,
    Shutdown,
    DcTcpInfo,
    Protocol,
    SkV6Only,
    Locals,
    Peers,
    Pad,
    Mark,
    BbrInfo,
    ClassId,
    Md5Sig,
    MAX,
}

impl InetDiagMsg {
    pub fn family(&self) -> Option<AddressFamily> {
        AddressFamily::from_i32(i32(self.family))
    }

    pub fn src_port(&self) -> u16 {
        u16::from_be(self.id.sport_be)
    }

    pub fn dst_port(&self) -> u16 {
        u16::from_be(self.id.dport_be)
    }

    pub fn src_addr(&self) -> Result<IpAddr, Error> {
        to_address(self.family, &self.id.src_be)
    }

    pub fn dst_addr(&self) -> Result<IpAddr, Error> {
        to_address(self.family, &self.id.dst_be)
    }

    pub fn state(&self) -> Option<State> {
        State::from_u8(self.state)
    }
}

impl RtaMessageType {
    pub fn from_short(i: c_short) -> Option<RtaMessageType> {
        if i >= 0 && i < RtaMessageType::MAX as c_short {
            Some(unsafe { mem::transmute(i) })
        } else {
            None
        }
    }
}

fn to_address(family: u8, data: &[u32; 4]) -> Result<IpAddr, Error> {
    Ok(match c_int::from(family) {
        AF_INET => IpAddr::V4(Ipv4Addr::from(u32::from_be(data[0]))),
        AF_INET6 => {
            let buf = unsafe { mem::transmute::<[u32; 4], [u8; 16]>(*data) };
            IpAddr::V6(Ipv6Addr::from(buf))
        }
        other => bail!("unrecognised address family: {}", other),
    })
}
