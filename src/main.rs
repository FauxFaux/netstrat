#[macro_use]
extern crate error_chain;
extern crate libc;
extern crate nix;

use nix::sys::socket::AddressFamily;
use nix::sys::socket::SockProtocol;

mod errors;
mod raw;

use errors::*;

fn callback(msg: raw::InetDiagMsg) {
    let id = unsafe { raw::inet_diag_msg_id(msg) };
    let family = unsafe { raw::inet_diag_msg_family(msg) };
    println!(
        "src: {:?}:{}, dst: {:?}:{}",
        unsafe { raw::to_address(family, raw::inet_diag_sockid_src(id)) },
        unsafe { raw::inet_diag_sockid_sport(id) },
        unsafe { raw::to_address(family, raw::inet_diag_sockid_dst(id)) },
        unsafe { raw::inet_diag_sockid_dport(id) },
    );
}

fn run() -> Result<()> {
    unsafe {
        let mut socket = raw::NetlinkDiag::new()?;
        socket.ask_ip(AddressFamily::Inet, SockProtocol::Tcp)?;
        let mut recv = socket.receive_until_done()?;
        while let Some(ptr) = recv.next()? {
            callback(ptr)
        }
    }
    Ok(())
}

quick_main!(run);
