#[macro_use]
extern crate error_chain;
extern crate pnetlink;
extern crate pnet_macros_support;

use pnetlink::socket;
use pnetlink::packet::netlink;
use pnet_macros_support::packet::Packet;

mod errors;

use errors::*;

const SOCK_DIAG_BY_FAMILY: u16 = 20;

fn send_all(nl: &mut socket::NetlinkSocket, buf: &[u8]) -> Result<()> {
    ensure!(buf.len() == nl.send(buf)?, "short send");
    Ok(())
}

fn run() -> Result<()> {
    let mut nl = socket::NetlinkSocket::bind(socket::NetlinkProtocol::Inet_diag, 0)?;
    let pkt = netlink::NetlinkRequestBuilder::new(SOCK_DIAG_BY_FAMILY, netlink::NetlinkMsgFlags::empty())
        .
        .build();
    send_all(&mut nl, pkt.packet())?;
    Ok(())
}

quick_main!(run);
'