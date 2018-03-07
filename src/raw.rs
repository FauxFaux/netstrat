#[link(name = "netstrat-native", kind = "static")]

use std::mem;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::os::unix::io::RawFd;
use std::slice;

use libc;
use libc::c_void;
use libc::c_int;
use libc::size_t;
use libc::ssize_t;

use libc::AF_INET;
use libc::AF_INET6;

use nix;
use nix::sys::socket;
use nix::sys::socket::AddressFamily;
use nix::sys::socket::SockType;
use nix::sys::socket::SockProtocol;

use errors::*;

pub type InetDiagMsg = *mut c_void;
pub type InetDiagSockId = *mut c_void;
pub type NlMsgHeader = *mut c_void;

extern "C" {
    fn list_sockets(cb: extern "C" fn(InetDiagMsg)) -> i32;

    fn send_diag_msg(fd: c_int, family: c_int, proto: c_int) -> ssize_t;

    fn nlmsg_ok(nlh: NlMsgHeader, numbytes: size_t) -> bool;
    fn nlmsg_next(nlh: NlMsgHeader, numbytes: &mut size_t) -> NlMsgHeader;
    fn nlmsg_data(nlh: NlMsgHeader) -> *mut c_void;

    fn nlmsg_type(nlh: NlMsgHeader) -> u16;
    fn nlmsg_len(nlh: NlMsgHeader) -> u32;

    pub fn inet_diag_msg_family(msg: InetDiagMsg) -> u8;

    pub fn inet_diag_sockid_sport(sockid: InetDiagSockId) -> u16;
    pub fn inet_diag_sockid_dport(sockid: InetDiagSockId) -> u16;

    pub fn inet_diag_sockid_src(sockid: InetDiagSockId) -> *mut u32;
    pub fn inet_diag_sockid_dst(sockid: InetDiagSockId) -> *mut u32;

    pub fn inet_diag_msg_id(diag_msg: InetDiagMsg) -> InetDiagSockId;
}

pub struct NetlinkDiag {
    fd: RawFd,
}

impl NetlinkDiag {
    pub fn new() -> Result<NetlinkDiag> {
        Ok(NetlinkDiag {
            fd: nix::errno::Errno::result(unsafe {
                libc::socket(
                    AddressFamily::Netlink as c_int,
                    SockType::Datagram as c_int,
                    libc::NETLINK_INET_DIAG,
                )
            })? as RawFd,
            //fd: socket(AddressFamily::Netlink, SockType::Datagram, SockFlag::SOCK_CLOEXEC, SockProtocol::from(libc::NETLINK_INET_DIAG))
            //  .chain_err(|| "opening netlink")
        })
    }

    pub fn ask_ip(&mut self, family: AddressFamily, proto: SockProtocol) -> Result<()> {
        nix::errno::Errno::result(unsafe {
            send_diag_msg(self.fd, family as c_int, proto as c_int)
        })?;
        Ok(())
    }

    pub fn receive_until_done(&mut self) -> Result<Recv> {
        let mut ret = Recv {
            fd: self.fd,
            buf: [0u8; 8 * 1024],
            valid_bytes: 0,
            ptr: 0 as *mut c_void,
        };

        ret.recv()?;

        Ok(ret)
    }
}

pub struct Recv {
    fd: RawFd,
    buf: [u8; 8 * 1024],
    valid_bytes: usize,
    ptr: NlMsgHeader,
}

impl Recv {
    fn recv(&mut self) -> Result<()> {
        self.valid_bytes = socket::recv(self.fd, &mut self.buf, socket::MsgFlags::empty())?;
        self.ptr = unsafe { mem::transmute(&mut self.buf) };
        println!("recv of {}", self.valid_bytes);
        Ok(())
    }

    fn ok(&mut self) -> bool {
        unsafe { nlmsg_ok(self.ptr, self.valid_bytes) }
    }

    fn advance(&mut self) {
        self.ptr = unsafe { nlmsg_next(self.ptr, &mut self.valid_bytes) };
    }

    /// unsafe: return value is potentially only valid until next call
    pub unsafe fn next(&mut self) -> Result<Option<InetDiagMsg>> {
        loop {
            if !self.ok() {
                self.recv()?;
                ensure!(self.ok(), "invalid after read; impossible");
            }

            const NLMSG_INET_DIAG: c_int = 20;

            match nlmsg_type(self.ptr) as c_int {
                libc::NLMSG_DONE => return Ok(None),
                libc::NLMSG_ERROR => bail!("netlink error"),
                libc::NLMSG_OVERRUN => bail!("netlink overrun"),
                libc::NLMSG_NOOP => self.advance(),
                NLMSG_INET_DIAG => {
                    let ret = nlmsg_data(self.ptr);
                    self.advance();
                    return Ok(Some(ret));
                }

                other => bail!("unsupported message type: {}", other),
            }
        }
    }
}

impl Drop for NetlinkDiag {
    fn drop(&mut self) {
        if 0 != unsafe { libc::close(self.fd) } {
            panic!("couldn't close fd {:?}", self.fd)
        }
    }
}

pub unsafe fn to_address(family: u8, data: *const u32) -> Result<IpAddr> {
    Ok(match family as c_int {
        AF_INET => IpAddr::V4(Ipv4Addr::from(u32::from_be(*data))),
        AF_INET6 => {
            let mut buf = [0u8; 16];
            buf.copy_from_slice(slice::from_raw_parts(
                mem::transmute::<*const u32, *const u8>(data),
                16,
            ));
            IpAddr::V6(Ipv6Addr::from(buf))
        }
        other => bail!("unrecognised address family: {}", other),
    })
}
