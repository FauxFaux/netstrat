#[macro_use]
extern crate error_chain;
extern crate libc;
extern crate nix;

use nix::sys::socket::AddressFamily;
use nix::sys::socket::SockProtocol;

mod errors;
mod raw;

use errors::*;

fn callback(msg: &raw::InetDiagMsg) {
    let id = &msg.id;
    println!(
        "src: {:?}:{}, dst: {:?}:{}",
        raw::to_address(msg.family, &id.src_be),
        u16::from_be(id.sport_be),
        raw::to_address(msg.family, &id.dst_be),
        u16::from_be(id.dport_be),
    );
}

fn run() -> Result<()> {
    let mut socket = raw::NetlinkDiag::new()?;
    socket.ask_ip(AddressFamily::Inet, SockProtocol::Tcp)?;
    let mut recv = socket.receive_until_done()?;
    while let Some(ptr) = unsafe { recv.next()? } {
        callback(ptr)
    }
    Ok(())
}

quick_main!(run);
