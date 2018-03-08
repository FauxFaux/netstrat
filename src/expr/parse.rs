use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::num::ParseIntError;
use std::result::Result as StdResult;
use std::str::FromStr;

use nom::IResult;
use nom::multispace;

use errors::*;
use expr::AddrFilter;
use expr::AddrMaskPort;
use expr::Expression;
use expr::Input;
use expr::Op;

named!(input<&str, Input>, alt_complete!(
    tag!("src") => { |_| Input::Src } |
    tag!("dst") => { |_| Input::Dst }
));

named!(op<&str, Op>, alt_complete!(
    tag!("eq") => { |_| Op::Eq } |
    tag!("=") => { |_| Op::Eq } |
    tag!("==") => { |_| Op::Eq }
));

fn parse_u8(input: &str) -> StdResult<u8, ParseIntError> {
    input.parse()
}

fn parse_u16(input: &str) -> StdResult<u16, ParseIntError> {
    input.parse()
}

fn digit(input: char) -> bool {
    input.is_ascii_digit()
}

named!(port<&str, u16>, preceded!(complete!(tag!(":")), alt_complete!(
    map_res!(take_while1_s!(digit), parse_u16) |
    tag!("*") => { |_| 0 }
)));

named!(octet<&str, u8>, map_res!(take_while1_s!(digit), parse_u8));

named!(mask<&str, u8>, preceded!(complete!(tag!("/")), octet));

named!(v4addr<&str, IpAddr>, do_parse!(
    a: octet >>
    tag!(".") >>
    b: octet >>
    tag!(".") >>
    c: octet >>
    tag!(".") >>
    d: octet >>
    ( Ipv4Addr::new(a, b, c, d).into() )
));

named!(v6addr<&str, IpAddr>, do_parse!(
    tag!("na") >>
    ( unimplemented!() )
));

named!(addr<&str, IpAddr>, alt_complete!(
    v4addr |
    delimited!(
        tag!("["),
        alt_complete!(
            v4addr |
            v6addr
        ),
        tag!("]")
    )
));

named!(amp_addr_opt_opt<&str, AddrMaskPort>, do_parse!(
    addr: addr >>
    mask: opt!(mask) >>
    port: opt!(port) >>
    ( AddrMaskPort {
        addr: Some(addr), mask, port
    } )
));

named!(amp_just_port<&str, AddrMaskPort>, do_parse!(
    port: port >>
    ( AddrMaskPort {
        addr: None, mask: None, port: Some(port)
    } )
));

named!(addr_mask_port<&str, AddrMaskPort>, alt_complete!(
    amp_addr_opt_opt |
    amp_just_port
));

named!(addr_expr<&str, Expression>, do_parse!(
    input: input >>
    many1!(multispace) >>
    op: op >>
    many1!(multispace) >>
    addr: addr_mask_port >>
    ( Expression::Addr(AddrFilter { input, op, addr })) )
);

#[cfg(test)]
mod tests {
    use super::*;

    use self::AddrFilter as AF;
    use self::AddrMaskPort as AMP;
    use self::Expression as E;

    #[test]
    fn parts() {
        assert_eq!(IResult::Done("", 2), octet("2"));
        assert_eq!(IResult::Done("", 2), port(":2"));
        assert_eq!(IResult::Done("", 4), mask("/4"));
        assert_eq!(IResult::Done("", 12), mask("/12"));
        assert_eq!(
            IResult::Done("", "0.0.0.0".parse::<Ipv4Addr>().unwrap().into()),
            addr("0.0.0.0")
        );
        assert_eq!(
            IResult::Done("", AMP::new_str_v4(Some("0.0.0.0"), None, None)),
            amp_addr_opt_opt("0.0.0.0")
        );
    }

    #[test]
    fn addr_expr_full() {
        assert_eq!(
            IResult::Done(
                "",
                E::Addr(AF {
                    input: Input::Src,
                    op: Op::Eq,
                    addr: AMP::new_str_v4(Some("0.0.0.0"), Some(0), Some(80)),
                })
            ),
            addr_expr("src eq 0.0.0.0/0:80")
        );
    }

    #[test]
    fn addr_expr_no_mask() {
        assert_eq!(
            IResult::Done(
                "",
                E::Addr(AF {
                    input: Input::Src,
                    op: Op::Eq,
                    addr: AMP::new_str_v4(Some("0.0.0.0"), None, Some(80)),
                })
            ),
            addr_expr("src eq 0.0.0.0:80")
        );
    }

    #[test]
    fn addr_expr_no_port() {
        assert_eq!(
            IResult::Done(
                "",
                E::Addr(AF {
                    input: Input::Src,
                    op: Op::Eq,
                    addr: AMP::new_str_v4(Some("0.0.0.0"), None, None),
                })
            ),
            addr_expr("src eq 0.0.0.0")
        );
    }

    #[test]
    fn addr_expr_no_addr() {
        assert_eq!(
            IResult::Done(
                "",
                E::Addr(AF {
                    input: Input::Src,
                    op: Op::Eq,
                    addr: AMP::new_str_v4(None, None, Some(80)),
                })
            ),
            addr_expr("src eq :80")
        );
    }
}
