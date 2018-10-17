#[macro_use]
extern crate bitflags;
extern crate cast;
extern crate clap;
extern crate dns_lookup;
#[macro_use]
extern crate failure;
extern crate libc;
extern crate nix;
#[macro_use]
extern crate nom;
extern crate rayon;

use std::collections::HashSet;
use std::io;
use std::io::Write;
use std::net::IpAddr;

use failure::Error;
use failure::ResultExt;
use nix::sys::socket::AddressFamily;
use nix::sys::socket::SockProtocol;
use rayon::iter::IntoParallelIterator;
use rayon::iter::ParallelIterator;

mod expr;
mod netlink;
mod pid_map;

use expr::Expression;
use netlink::tcp::State;
use netlink::InetDiag;
use pid_map::PidMap;

// Oh, how I wish to punish those ipv4 users.
fn render_address(addr: &IpAddr) -> String {
    match *addr {
        IpAddr::V4(addr) => format!("{}", addr),
        IpAddr::V6(addr) => format!("[{}]", addr),
    }
}

fn disp_proto_state<W: Write>(
    mut into: W,
    proto: SockProtocol,
    diag: &netlink::InetDiag,
) -> Result<(), io::Error> {
    write!(
        into,
        "{}{} {:6} ",
        match proto {
            SockProtocol::Tcp => "tcp",
            SockProtocol::Udp => "udp",
        },
        match diag.msg.family() {
            Some(AddressFamily::Inet) => "4".to_string(),
            Some(AddressFamily::Inet6) => "6".to_string(),
            other => format!("?? {:?}", other),
        },
        diag.msg
            .state()
            // Don't display "CLOSED" for closed UDP sockets, as this also means "Listening".
            .filter(|&state| SockProtocol::Udp != proto || state != State::Closed)
            .map(|state| state.abbr())
            .unwrap_or("")
    )
}

fn disp_queues<W: Write>(mut into: W, diag: &InetDiag) -> io::Result<()> {
    write!(into, "{:6} {:6} ", diag.msg.rqueue, diag.msg.wqueue)
}

fn disp_addr<W: Write>(mut into: W, width: usize, addr: &str, port: u16) -> Result<(), io::Error> {
    write!(into, "{:>width$}:{:<5} ", addr, port, width = width)
}

fn disp_user_proc<W: Write>(
    mut into: W,
    diag: &InetDiag,
    pid_map: Option<&PidMap>,
) -> io::Result<()> {
    write!(into, "{:5} ", diag.msg.uid)?;

    if let Some(pid_map) = pid_map {
        match pid_map.get(&diag.msg.inode) {
            Some(info) => write!(into, " {:>5}/{}", info.pid, info.process_name())?,
            None => write!(into, "      -")?,
        }
    }

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
                .help("use narrow output (blocks; implies sort, --resolve, -H)"),
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
    pid NUMBER     (TODO)
    app SHORT-NAME (TODO)
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
                "warning: Couldn't read some values from /proc, do you have permission?"
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

    const MAX_EXPECTED_ADDR_LENGTH: usize = 41;

    let mut entries = Vec::with_capacity(64);
    let mut socket = netlink::NetlinkDiag::new()?;
    for family in families {
        for &proto in &[SockProtocol::Tcp, SockProtocol::Udp] {
            socket.ask_ip(family, proto)?;
            let mut recv = socket.receive_until_done()?;
            while let Some(ref diag) = recv.next()? {
                if !expression.matches(diag, pid_map) {
                    continue;
                }

                if narrow {
                    entries.push((proto, *diag));
                    continue;
                }

                let stdout = io::stdout();
                let mut stdout = stdout.lock();
                disp_proto_state(&mut stdout, proto, &diag)?;
                disp_queues(&mut stdout, &diag)?;
                disp_addr(
                    &mut stdout,
                    MAX_EXPECTED_ADDR_LENGTH,
                    &diag.msg.src_addr_str()?,
                    diag.msg.src_port(),
                )?;
                disp_addr(
                    &mut stdout,
                    MAX_EXPECTED_ADDR_LENGTH,
                    &diag.msg.dst_addr_str()?,
                    diag.msg.dst_port(),
                )?;
                disp_user_proc(&mut stdout, &diag, pid_map)?;
                writeln!(stdout);
            }
        }
    }

    if narrow && !entries.is_empty() {
        let mut entries: Vec<(SockProtocol, InetDiag, String, String)> = entries
            .into_par_iter()
            .map(|(proto, diag)| -> Result<_, Error> {
                Ok((
                    proto,
                    diag,
                    silent_to_name(&diag.msg.src_addr()?, diag.msg.src_port()),
                    silent_to_name(&diag.msg.dst_addr()?, diag.msg.dst_port()),
                ))
            })
            .collect::<Result<_, Error>>()?;

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

        entries.sort_unstable_by(|(lp, ld, lsrc, ldst), (rp, rd, rsrc, rdst)| {
            fn proto_order(proto: &SockProtocol) -> u8 {
                match proto {
                    SockProtocol::Tcp => 0,
                    SockProtocol::Udp => 1,
                }
            }

            fn state_order(state: Option<State>) -> u8 {
                match state {
                    Some(State::Listen) => 0,
                    Some(State::Established) => 1,
                    Some(_other_state) => 2,
                    None => 3,
                }
            }

            proto_order(lp)
                .cmp(&proto_order(rp))
                .then(state_order(ld.msg.state()).cmp(&state_order(rd.msg.state())))
                .then(ld.msg.dst_port().cmp(&rd.msg.dst_port()))
                .then(ld.msg.src_port().cmp(&rd.msg.src_port()))
                .then(lsrc.cmp(rsrc))
                .then(ldst.cmp(rdst))
        });

        for (proto, diag, src_addr, dst_addr) in entries {
            let stdout = io::stdout();
            let mut stdout = stdout.lock();
            disp_proto_state(&mut stdout, proto, &diag)?;
            // *not* disp_queues
            disp_addr(&mut stdout, max_src_len, &src_addr, diag.msg.src_port())?;
            disp_addr(&mut stdout, max_dst_len, &dst_addr, diag.msg.dst_port())?;
            disp_user_proc(&mut stdout, &diag, pid_map)?;
            writeln!(stdout);
        }
    }
    Ok(())
}

fn silent_to_name(addr: &IpAddr, port: u16) -> String {
    match dns_lookup::getnameinfo(&(*addr, port).into(), libc::NI_NAMEREQD | libc::NI_NOFQDN) {
        Ok((name, _)) => name,
        Err(_) => render_address(&addr),
    }
}
