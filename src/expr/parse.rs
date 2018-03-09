use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::AddrParseError;
use std::num::ParseIntError;
use std::result::Result as StdResult;
use std::str::FromStr;

use nom::types::CompleteStr;
use nom::IResult;
use nom::multispace;

use errors::*;
use expr::AddrFilter;
use expr::AddrMaskPort;
use expr::Expression;
use expr::Input;
use expr::Op;

named!(input<CompleteStr, Input>, alt_complete!(
    tag!("src") => { |_| Input::Src } |
    tag!("dst") => { |_| Input::Dst }
));

named!(op<CompleteStr, Op>, alt_complete!(
    tag!("eq") => { |_| Op::Eq } |
    tag!("=") => { |_| Op::Eq } |
    tag!("==") => { |_| Op::Eq }
));

fn parse_u8(input: CompleteStr) -> StdResult<u8, ParseIntError> {
    input.0.parse()
}

fn parse_u16(input: CompleteStr) -> StdResult<u16, ParseIntError> {
    input.0.parse()
}

fn parse_quad(input: CompleteStr) -> StdResult<u16, ParseIntError> {
    u16::from_str_radix(input.0, 16)
}

fn parse_v6(input: CompleteStr) -> StdResult<IpAddr, AddrParseError> {
    Ok(input.0.parse::<Ipv6Addr>()?.into())
}

fn digit(input: char) -> bool {
    input.is_ascii_digit()
}

fn hex_digit(input: char) -> bool {
    input.is_ascii_hexdigit()
}

named!(port<CompleteStr, u16>, preceded!(complete!(tag!(":")), alt_complete!(
    map_res!(take_while1_s!(digit), parse_u16) |
    tag!("*") => { |_| 0 }
)));

// TODO: I'd love `do_parse!()` instead of this `map_res!` and helper nonsense,
// TODO: but it doesn't seem to consume the input, and I don't get why.
named!(octet<CompleteStr, u8>, map_res!(take_while1_s!(digit), parse_u8));

named!(quad<CompleteStr, u16>, map_res!(take_while1_s!(hex_digit), parse_quad));

named!(mask<CompleteStr, u8>, preceded!(complete!(tag!("/")), octet));

named!(v4addr<CompleteStr, IpAddr>, do_parse!(
    a: octet >>
    tag!(".") >>
    b: octet >>
    tag!(".") >>
    c: octet >>
    tag!(".") >>
    d: octet >>
    ( Ipv4Addr::new(a, b, c, d).into() )
));

named!(v6addr_full<CompleteStr, IpAddr>, do_parse!(
    a: quad >>
    b: count_fixed!(
        u16,
        preceded!(tag!(":"), quad),
        7
    ) >>
    ( Ipv6Addr::new(a, b[0], b[1], b[2], b[3], b[4], b[5], b[6]).into() )
));

named!(v6_quads<CompleteStr, Vec<u16>>, separated_list_complete!(
    tag!(":"),
    quad
));

// TODO: could take the actual parsed u16s out of this, recombine them by hand
// TODO: if the length was right, and build the address directly
named!(v6addr_abbr_match<CompleteStr, CompleteStr>, recognize!(do_parse!(
    _before: v6_quads >>
    tag!("::") >>
    _after: v6_quads >>
    ()
)));

named!(v6addr_abbr<CompleteStr, IpAddr>,
    map_res!(v6addr_abbr_match, parse_v6)
);

named!(v6addr<CompleteStr, IpAddr>, alt_complete!(
    v6addr_abbr |
    v6addr_full
));

named!(addr<CompleteStr, IpAddr>, alt_complete!(
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

named!(amp_addr_opt_opt<CompleteStr, AddrMaskPort>, do_parse!(
    addr: addr >>
    mask: opt!(mask) >>
    port: opt!(port) >>
    ( AddrMaskPort {
        addr: Some(addr), mask, port
    } )
));

named!(amp_just_port<CompleteStr, AddrMaskPort>, do_parse!(
    port: port >>
    ( AddrMaskPort {
        addr: None, mask: None, port: Some(port)
    } )
));

named!(addr_mask_port<CompleteStr, AddrMaskPort>, alt_complete!(
    amp_addr_opt_opt |
    amp_just_port
));

named!(addr_expr<CompleteStr, Expression>, do_parse!(
    input: input >>
    many1!(multispace) >>
    op: op >>
    many1!(multispace) >>
    addr: addr_mask_port >>
    ( Expression::Addr(AddrFilter { input, op, addr })) )
);

fn explain(result: IResult<CompleteStr, Expression>) -> String {
    format!("{:?}", result)
}

#[cfg(test)]
mod tests {
    use super::*;

    use self::AddrFilter as AF;
    use self::AddrMaskPort as AMP;
    use self::Expression as E;

    #[test]
    fn parts() {
        assert_eq!(Ok((CompleteStr(""), 2)), octet(CompleteStr("2")));
        assert_eq!(Ok((CompleteStr(""), 2)), port(CompleteStr(":2")));
        assert_eq!(Ok((CompleteStr(""), 4)), mask(CompleteStr("/4")));
        assert_eq!(Ok((CompleteStr(""), 12)), mask(CompleteStr("/12")));
        assert_eq!(
            Ok((CompleteStr(""), "0.0.0.0".parse::<Ipv4Addr>().unwrap().into())),
            addr(CompleteStr("0.0.0.0"))
        );
        assert_eq!(
            Ok((CompleteStr(""), "::".parse::<Ipv6Addr>().unwrap().into())),
            addr(CompleteStr("[::]"))
        );
        assert_eq!(
            Ok((
                CompleteStr(""),
                "2001:db8:0:0:1::1".parse::<Ipv6Addr>().unwrap().into()
            )),
            addr(CompleteStr("[2001:db8::1:0:0:1]"))
        );
        assert_eq!(
            Ok((
                CompleteStr(""),
                "2001:db8:0:0:1:0:0:1".parse::<Ipv6Addr>().unwrap().into()
            )),
            addr(CompleteStr("[2001:db8:0:0:1:0:0:1]"))
        );
        assert_eq!(
            Ok((CompleteStr(""), AMP::new_str_v4(Some("0.0.0.0"), None, None))),
            amp_addr_opt_opt(CompleteStr("0.0.0.0"))
        );
    }

    #[test]
    fn addr_expr_full() {
        assert_eq!(
            Ok((
                CompleteStr(""),
                E::Addr(AF {
                    input: Input::Src,
                    op: Op::Eq,
                    addr: AMP::new_str_v4(Some("0.0.0.0"), Some(0), Some(80)),
                })
            )),
            addr_expr(CompleteStr("src eq 0.0.0.0/0:80"))
        );
    }

    #[test]
    fn addr_expr_no_mask() {
        assert_eq!(
            Ok((
                CompleteStr(""),
                E::Addr(AF {
                    input: Input::Src,
                    op: Op::Eq,
                    addr: AMP::new_str_v4(Some("0.0.0.0"), None, Some(80)),
                })
            )),
            addr_expr(CompleteStr("src eq 0.0.0.0:80"))
        );
    }

    #[test]
    fn addr_expr_no_port() {
        assert_eq!(
            Ok((
                CompleteStr(""),
                E::Addr(AF {
                    input: Input::Src,
                    op: Op::Eq,
                    addr: AMP::new_str_v4(Some("0.0.0.0"), None, None),
                })
            )),
            addr_expr(CompleteStr("src eq 0.0.0.0"))
        );
    }

    #[test]
    fn addr_expr_no_addr() {
        assert_eq!(
            Ok((
                CompleteStr(""),
                E::Addr(AF {
                    input: Input::Src,
                    op: Op::Eq,
                    addr: AMP::new_str_v4(None, None, Some(80)),
                })
            )),
            addr_expr(CompleteStr("src eq :80"))
        );
    }

    #[ignore]
    #[test]
    fn error_bad_addr() {
        assert_eq!("nope", explain(addr_expr(CompleteStr("src eq _"))));
    }
}
