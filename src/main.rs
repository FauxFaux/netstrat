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

fn dump_tcp(msg: &raw::InetDiagMsg) -> Result<()> {
    println!(
        "tcp{} src: {}, dst: {}, uid: {}",
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
    for family in &[AddressFamily::Inet, AddressFamily::Inet6] {
        socket.ask_ip(*family, SockProtocol::Tcp)?;
        let mut recv = socket.receive_until_done()?;
        while let Some(ptr) = unsafe { recv.next()? } {
            dump_tcp(ptr)?;
        }
    }
    Ok(())
}

quick_main!(run);
