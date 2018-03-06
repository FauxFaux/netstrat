#[macro_use]
extern crate error_chain;
extern crate libc;

use errors::*;

mod errors;
mod raw;

extern fn callback(msg: raw::InetDiagMsg) {
    let id = unsafe { raw::inet_diag_msg_id(msg) };
    let family = unsafe { raw::inet_diag_msg_family(msg) };
    println!("src: {:?}:{}, dst: {:?}:{}",
             unsafe { raw::to_address(family, raw::inet_diag_sockid_src(id)) },
             unsafe { raw::inet_diag_sockid_sport(id) },
             unsafe { raw::to_address(family, raw::inet_diag_sockid_dst(id)) },
             unsafe { raw::inet_diag_sockid_dport(id) },
    );
}

fn run() -> Result<()> {
    unsafe {
        raw::list_sockets(callback);
    }
    Ok(())
}

quick_main!(run);
