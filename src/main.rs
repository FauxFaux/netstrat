extern crate cast;
#[macro_use]
extern crate error_chain;
extern crate libc;
extern crate nix;

use std::net::IpAddr;

use nix::sys::socket::AddressFamily;
use nix::sys::socket::SockProtocol;

mod errors;
mod raw;

use errors::*;

fn render_address(addr: &IpAddr, port: u16) -> String {
    match *addr {
        IpAddr::V4(addr) => format!("{}:{}", addr, port),
        IpAddr::V6(addr) => format!("[{}]:{}", addr, port),
    }
}

fn dump_proto(proto: SockProtocol, msg: &raw::InetDiagMsg) -> Result<()> {
    println!(
        "{}{} src: {}, dst: {}, uid: {}",
        match proto {
            SockProtocol::Tcp => "tcp",
            SockProtocol::Udp => "udp",
            _ => unimplemented!()
        },
        match msg.family() {
            Some(AddressFamily::Inet) => "4".to_string(),
            Some(AddressFamily::Inet6) => "6".to_string(),
            other => format!("?? {:?}", other),
        },
        render_address(&msg.src_addr()?, msg.src_port()),
        render_address(&msg.dst_addr()?, msg.dst_port()),
        msg.uid
    );

    Ok(())
}

fn run() -> Result<()> {
    let mut socket = raw::NetlinkDiag::new()?;
    for &proto in &[SockProtocol::Tcp, SockProtocol::Udp] {
        for &family in &[AddressFamily::Inet, AddressFamily::Inet6] {
            socket.ask_ip(family, proto)?;
            let mut recv = socket.receive_until_done()?;
            while let Some(ptr) = unsafe { recv.next()? } {
                dump_proto(proto, ptr)?;
            }
        }
    }
    Ok(())
}

quick_main!(run);
