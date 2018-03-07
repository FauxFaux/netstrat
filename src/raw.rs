#[link(name = "netstrat-native", kind = "static")]

use std::mem;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::os::unix::io::RawFd;

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

pub type NlMsgHeader = c_void;

extern "C" {
    fn send_diag_msg(fd: c_int, family: c_int, proto: c_int) -> ssize_t;

    fn nlmsg_ok(nlh: *const NlMsgHeader, numbytes: size_t) -> bool;
    fn nlmsg_next(nlh: *const NlMsgHeader, numbytes: &mut size_t) -> *const NlMsgHeader;
    fn nlmsg_data(nlh: *const NlMsgHeader) -> *mut c_void;

    fn nlmsg_type(nlh: *const NlMsgHeader) -> u16;
    fn nlmsg_len(nlh: *const NlMsgHeader) -> u32;
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
    ptr: *const NlMsgHeader,
}

impl Recv {
    fn recv(&mut self) -> Result<()> {
        self.valid_bytes = socket::recv(self.fd, &mut self.buf, socket::MsgFlags::empty())?;
        self.ptr = unsafe { mem::transmute(&mut self.buf) };
        Ok(())
    }

    fn ok(&mut self) -> bool {
        unsafe { nlmsg_ok(self.ptr, self.valid_bytes) }
    }

    fn advance(&mut self) {
        self.ptr = unsafe { nlmsg_next(self.ptr, &mut self.valid_bytes) };
    }

    /// unsafe: return value is potentially only valid until next call
    pub unsafe fn next(&mut self) -> Result<Option<&InetDiagMsg>> {
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
                    return Ok(Some(&(*(ret as *const InetDiagMsg))));
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

pub fn to_address(family: u8, data: &[u32; 4]) -> Result<IpAddr> {
    Ok(match family as c_int {
        AF_INET => IpAddr::V4(Ipv4Addr::from(u32::from_be(data[0]))),
        AF_INET6 => {
            let mut buf = unsafe { mem::transmute::<[u32; 4], [u8; 16]>(*data) };
            IpAddr::V6(Ipv6Addr::from(buf))
        }
        other => bail!("unrecognised address family: {}", other),
    })
}

#[repr(C)]
pub struct InetDiagSockId {
    pub sport_be: u16,
    pub dport_be: u16,
    pub src_be: [u32; 4],
    pub dst_be: [u32; 4],
    pub iface: u32,
    pub cookie: [u32; 4],
}

#[repr(C)]
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
