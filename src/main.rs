#[macro_use]
extern crate bitflags;
extern crate cast;
extern crate clap;
#[macro_use]
extern crate failure;
extern crate libc;
extern crate nix;
#[macro_use]
extern crate nom;

use std::collections::HashSet;
use std::io;
use std::io::Write;
use std::net::IpAddr;

use failure::Error;
use failure::ResultExt;
use nix::sys::socket::AddressFamily;
use nix::sys::socket::SockProtocol;

mod expr;
mod netlink;
mod pid_map;

use expr::Expression;
use netlink::tcp::State;
use pid_map::PidMap;

// Oh, how I wish to punish those ipv4 users.
fn render_address(addr: &IpAddr) -> String {
    match *addr {
        IpAddr::V4(addr) => format!("{}", addr),
        IpAddr::V6(addr) => format!("[{}]", addr),
    }
}

fn dump_proto(
    proto: SockProtocol,
    msg: &netlink::InetDiag,
    map: Option<&PidMap>,
    (src_width, dst_width): (usize, usize),
    src_addr: &str,
    dst_addr: &str,
) -> Result<(), Error> {
    print!(
        "{}{} {:6} {:6} {:6} {:>src_width$}:{:<5} {:>dst_width$}:{:<5} {:5}",
        match proto {
            SockProtocol::Tcp => "tcp",
            SockProtocol::Udp => "udp",
        },
        match msg.msg.family() {
            Some(AddressFamily::Inet) => "4".to_string(),
            Some(AddressFamily::Inet6) => "6".to_string(),
            other => format!("?? {:?}", other),
        },
        msg.msg
            .state()
            // Don't display "CLOSED" for closed UDP sockets, as this also means "Listening".
            .filter(|&state| SockProtocol::Udp != proto || state != State::Closed)
            .map(|state| state.abbr())
            .unwrap_or(""),
        msg.msg.rqueue,
        msg.msg.wqueue,
        src_addr,
        msg.msg.src_port(),
        dst_addr,
        msg.msg.dst_port(),
        msg.msg.uid,
        src_width = src_width,
        dst_width = dst_width,
    );

    if let Some(map) = map {
        match map.get(&msg.msg.inode) {
            Some(info) => print!(" {:>5}/{}", info.pid, info.process_name()),
            None => print!("      -"),
        }
    }

    println!();

    Ok(())
}

fn main() -> Result<(), Error> {
    use clap::Arg;
    let matches = clap::App::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .about("Filter system sockets by family, then protocol, then a given expression")
        .setting(clap::AppSettings::DeriveDisplayOrder)
        .setting(clap::AppSettings::UnifiedHelpMessage)
        // n/r (not-)resolve (default: not)
        // a/l: fiddling with the state filter; default is:
        //      all minus listening, closed, time_wait, syn_recv
        // 4/6: show only this family (default: all?)
        // t/S[ctp]/u/d[ccp]/[ra]w/[uni]x/U[dplite]: show only this type, default all
        // H: no header
        .arg(
            Arg::with_name("resolve")
                .long("resolve")
                .short("r")
                .help("lookup names, ports and users"),
        )
        .arg(
            Arg::with_name("numeric")
                .long("numeric")
                .short("n")
                .help("don't lookup names, ports or users"),
        )
        .arg(
            Arg::with_name("programs")
                .long("programs")
                .short("p")
                .help("lookup owning process pid"),
        )
        .arg(
            Arg::with_name("narrow")
                .long("narrow")
                .short("W")
                .help("use narrow output (blocks until data is complete)"),
        )
        // ---
        .arg(
            Arg::with_name("all")
                .short("a")
                .help("enable all supported types and perform no filtering (currently a noop)"),
        )
        .arg(
            Arg::with_name("connected")
                .short("c")
                .help("start with a filter of 'state connected'"),
        )
        .arg(
            Arg::with_name("listening")
                .short("l")
                .help("start with a filter of 'state listening'"),
        )
        // ---
        .arg(
            Arg::with_name("family")
                .long("family")
                .short("f")
                .takes_value(true)
                .possible_values(&["inet", "inet6"])
                .multiple(true)
                .require_delimiter(true)
                .help("only include these families"),
        )
        .arg(
            Arg::with_name("4")
                .short("4")
                .help("short for '--family=inet'"),
        )
        .arg(
            Arg::with_name("6")
                .short("6")
                .help("short for '--family=inet6'"),
        )
        // ---
        .arg(Arg::with_name("filter").help("filter expression"))
        // ---
        .arg(
            Arg::with_name("no-header")
                .long("no-header")
                .short("H")
                .help("don't emit header row"),
        )
        .after_help(
            r"FILTER:
    state {all|connected|synchronised|bucket|big|...}
    {either|src|dest} {=|neq|<|≥} [ADDR][/MASK][:PORT]
    pid NUMBER
    app SHORT-NAME
    port PORT      (sugar for 'either = :PORT')

    EXPR and (EXPR || EXPR)

DEFAULTS:
    --family inet,inet6
    --proto  tcp,udp

Defaults are used if no overriding argument of that group is provided.",
        )
        .get_matches();

    let expression = if let Some(filter) = matches.value_of("filter") {
        expr::parse(filter)
            .with_context(|_| format_err!("interpreting filter expression"))?
            .simplify()
    } else {
        Expression::Yes
    };

    let pid_map = if matches.is_present("programs") {
        let (pid_failures, pid_map) = pid_map::walk("/proc")?;
        if pid_failures {
            writeln!(
                io::stderr(),
                "Couldn't read some values from /proc, do you have permission?"
            )?;
        }
        Some(pid_map)
    } else {
        None
    };
    let pid_map = pid_map.as_ref();

    let mut families = HashSet::with_capacity(2);
    if matches.is_present("4") {
        families.insert(AddressFamily::Inet);
    }
    if matches.is_present("6") {
        families.insert(AddressFamily::Inet6);
    }
    if let Some(values) = matches.values_of("family") {
        for family in values {
            families.insert(match family {
                "inet" => AddressFamily::Inet,
                "inet6" => AddressFamily::Inet6,
                other => unreachable!("invalid family value {:?}", other),
            });
        }
    }

    if families.is_empty() {
        families.extend(&[AddressFamily::Inet, AddressFamily::Inet6]);
    }

    let mut families: Vec<AddressFamily> = families.into_iter().collect();
    families.sort_unstable_by_key(|&x| x as i32);
    let families = families;

    let narrow = matches.is_present("narrow");
    let no_header = !matches.is_present("no-header");

    if !narrow && no_header {
        print!(concat!(
            "prot state  recv-q send-q ",
            "                           source address:port",
            "                        destination address:port",
            "   uid"
        ));
        if pid_map.is_some() {
            print!("    pid/program");
        }

        println!();
    }

    let mut entries = Vec::with_capacity(64);
    let mut socket = netlink::NetlinkDiag::new()?;
    for family in families {
        for &proto in &[SockProtocol::Tcp, SockProtocol::Udp] {
            socket.ask_ip(family, proto)?;
            let mut recv = socket.receive_until_done()?;
            while let Some(ref msg) = recv.next()? {
                if expression.matches(msg, pid_map) {
                    if narrow {
                        entries.push((proto, *msg));
                    } else {
                        dump_proto(
                            proto,
                            msg,
                            pid_map,
                            (41, 41),
                            &msg.msg.src_addr_str()?,
                            &msg.msg.dst_addr_str()?,
                        )?;
                    }
                }
            }
        }
    }

    if narrow && !entries.is_empty() {
        let entries = entries
            .into_iter()
            .map(|(proto, msg)| -> Result<_, Error> {
                Ok((
                    proto,
                    msg,
                    render_address(&msg.msg.src_addr()?),
                    render_address(&msg.msg.dst_addr()?),
                ))
            })
            .collect::<Result<Vec<_>, Error>>()?;

        let max_src_len = entries
            .iter()
            .map(|(_, _, src, _dst)| src.len())
            .max()
            .expect("!is_empty");
        let max_dst_len = entries
            .iter()
            .map(|(_, _, _src, dst)| dst.len())
            .max()
            .expect("!is_empty");

        for (proto, diag, src_addr, dst_addr) in entries {
            dump_proto(
                proto,
                &diag,
                pid_map,
                (max_src_len, max_dst_len),
                &src_addr,
                &dst_addr,
            )?;
        }
    }
    Ok(())
}
