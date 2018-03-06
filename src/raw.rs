#[link(name = "netstrat-native", kind = "static")]

use std::mem;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::slice;

use libc::c_void;
use libc::c_int;

use libc::AF_INET;
use libc::AF_INET6;

use errors::*;

pub type InetDiagMsg = *mut c_void;
pub type InetDiagSockId = *mut c_void;

extern {
    pub fn list_sockets(cb: extern fn(InetDiagMsg)) -> i32;

    pub fn inet_diag_msg_family(msg: InetDiagMsg) -> u8;

    pub fn inet_diag_sockid_sport(sockid: InetDiagSockId) -> u16;
    pub fn inet_diag_sockid_dport(sockid: InetDiagSockId) -> u16;

    pub fn inet_diag_sockid_src(sockid: InetDiagSockId) -> *mut u32;
    pub fn inet_diag_sockid_dst(sockid: InetDiagSockId) -> *mut u32;

    pub fn inet_diag_msg_id(diag_msg: InetDiagMsg) -> InetDiagSockId;
}

pub unsafe fn to_address(family: u8, data: *const u32) -> Result<IpAddr> {
    Ok(match family as c_int {
        AF_INET => IpAddr::V4(Ipv4Addr::from(u32::from_be(*data))),
        AF_INET6 => {
            let mut buf = [0u8; 16];
            buf.copy_from_slice(slice::from_raw_parts(mem::transmute::<*const u32, *const u8>(data), 16));
            IpAddr::V6(Ipv6Addr::from(buf))
        },
        other => bail!("unrecognised address family: {}", other),
    })
}
