use std::net::AddrParseError;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::num::ParseIntError;
use std::result::Result as StdResult;

use nom::Context;
use nom::Err;
use nom::ErrorKind as NomKind;
use nom::multispace;
use nom::types::CompleteStr;

use errors::*;
use expr::AddrFilter;
use expr::AddrMaskPort;
use expr::Expression;
use expr::Input;
use expr::Op;
use expr::State;

named!(mandatory_whitespace<CompleteStr, CompleteStr>, add_return_error!(ErrorKind::Custom(100),
    call!(multispace)
));

named!(input<CompleteStr, Input>, add_return_error!(ErrorKind::Custom(1),
    alt_complete!(
        tag!("sport")  => { |_| Input::SrcPort } |
        tag!("dport")  => { |_| Input::DstPort } |
        tag!("src")    => { |_| Input::Src } |
        tag!("dst")    => { |_| Input::Dst } |
        tag!("any")    => { |_| Input::Either } |
        tag!("either") => { |_| Input::Either }
)));

named!(op<CompleteStr, Op>, add_return_error!(ErrorKind::Custom(2),
    alt_complete!(
        tag!("eq")  => { |_| Op::Eq } |
        tag!("==")  => { |_| Op::Eq } |
        tag!("=")   => { |_| Op::Eq } |

        tag!("neq") => { |_| Op::Ne } |
        tag!("ne")  => { |_| Op::Ne } |
        tag!("≠")   => { |_| Op::Ne } |
        tag!("!=")  => { |_| Op::Ne } |

        tag!("geq") => { |_| Op::Ge } |
        tag!("ge")  => { |_| Op::Ge } |
        tag!(">=")  => { |_| Op::Ge } |
        tag!("≥")   => { |_| Op::Ge } |

        tag!("leq") => { |_| Op::Le } |
        tag!("le")  => { |_| Op::Le } |
        tag!("<=")  => { |_| Op::Le } |
        tag!("≤")   => { |_| Op::Le } |

        tag!("gt")  => { |_| Op::Gt } |
        tag!(">")   => { |_| Op::Gt } |

        tag!("lt")  => { |_| Op::Lt } |
        tag!("<")   => { |_| Op::Lt }
)));

named!(state<CompleteStr, State>, add_return_error!(ErrorKind::Custom(3),
    alt_complete!(
        tag!("connected")    => { |_| State::connected() } |
        tag!("established")  => { |_| State::ESTABLISHED }
    // TODO
)));

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

named!(v4addr<CompleteStr, IpAddr>, add_return_error!(ErrorKind::Custom(20),
    do_parse!(
        a: octet >>
        tag!(".") >>
        b: octet >>
        tag!(".") >>
        c: octet >>
        tag!(".") >>
        d: octet >>
        ( Ipv4Addr::new(a, b, c, d).into() )
)));

named!(v6addr_full<CompleteStr, IpAddr>, add_return_error!(ErrorKind::Custom(21),
    do_parse!(
        a: quad >>
        b: count_fixed!(
            u16,
            preceded!(tag!(":"), quad),
            7
        ) >>
        ( Ipv6Addr::new(a, b[0], b[1], b[2], b[3], b[4], b[5], b[6]).into() )
)));

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

named!(v6addr_abbr<CompleteStr, IpAddr>, add_return_error!(ErrorKind::Custom(22),
    map_res!(v6addr_abbr_match, parse_v6)
));

named!(v6addr<CompleteStr, IpAddr>, add_return_error!(ErrorKind::Custom(23),
    alt_complete!(
        v6addr_abbr |
        v6addr_full
)));

named!(addr<CompleteStr, IpAddr>, add_return_error!(ErrorKind::Custom(24),
    alt_complete!(
        v4addr |
        delimited!(
            tag!("["),
            alt_complete!(
                v4addr |
                v6addr
            ),
            tag!("]")
        )
)));

named!(amp_addr_opt_opt<CompleteStr, AddrMaskPort>, add_return_error!(ErrorKind::Custom(40),
    do_parse!(
        addr: addr >>
        mask: opt!(mask) >>
        port: opt!(port) >>
        ( AddrMaskPort {
            addr: Some(addr), mask, port
        } )
)));

named!(amp_just_port<CompleteStr, AddrMaskPort>, add_return_error!(ErrorKind::Custom(41),
    do_parse!(
        port: port >>
        ( AddrMaskPort {
            addr: None, mask: None, port: Some(port)
        } )
)));

named!(addr_mask_port<CompleteStr, AddrMaskPort>, add_return_error!(ErrorKind::Custom(42),
    alt_complete!(
        amp_addr_opt_opt |
        amp_just_port
)));

named!(addr_expr<CompleteStr, Expression>, add_return_error!(ErrorKind::Custom(60),
    do_parse!(
        input: input >>
        mandatory_whitespace >>
        op: op >>
        mandatory_whitespace >>
        addr: addr_mask_port >>
        ( Expression::Addr(AddrFilter { input, op, addr })) )
));

named!(state_expr<CompleteStr, Expression>, add_return_error!(ErrorKind::Custom(61),
    do_parse!(
        tag!("state") >>
        mandatory_whitespace >>
        state: return_error!(ErrorKind::Custom(62), state) >>
        ( Expression::State(state) )
)));

named!(single_expr<CompleteStr, Expression>, add_return_error!(ErrorKind::Custom(70),
    alt_complete!(
        addr_expr |
        state_expr
)));

pub fn parse(input: &str) -> Result<Expression> {
    match single_expr(CompleteStr(input)) {
        Ok((CompleteStr(""), expr)) => Ok(expr),
        Ok((tail, val)) => bail!(
            "illegal trailing data: {:?}, after successfully parsing: {:?}",
            tail.0,
            val
        ),
        Err(Err::Error(e)) => Err(translate_nom_error(input, e, "syntax error in expression")),
        Err(Err::Failure(e)) => Err(translate_nom_error(input, e, "invalid value in expression")),
        Err(Err::Incomplete(_)) => unreachable!(),
    }
}

fn translate_nom_error(input: &str, e: Context<CompleteStr, u32>, problem: &str) -> Error {
    let mut v = super::nom_util::prepare_errors(input, e);
    v.reverse();
    let mut problem = ErrorKind::Msg(problem.to_string()).into();
    for (kind, start, end) in v {
        problem = Error::with_chain(
            problem,
            format!(
                "failed to parse '{}' near ... {} ...",
                translate(kind),
                &input[start..end]
            ),
        );
    }
    problem
}

fn translate(kind: NomKind) -> String {
    match kind {
        NomKind::Custom(code) => match code {
            1 => "input".to_string(),
            2 => "operator".to_string(),
            3 => "state literal".to_string(),
            20 => "ipv4 address".to_string(),
            21 => "full ipv6 address".to_string(),
            22 => "abbreviated ipv6 address".to_string(),
            23 => "ipv6 address".to_string(),
            24 => "address".to_string(),
            40 => "address with optional mask/port".to_string(),
            41 => ":port without address".to_string(),
            42 => "address/mask:port".to_string(),
            60 => "address filter".to_string(),
            61 => "state filter".to_string(),
            62 => "'state' argument ".to_string(),
            70 => "filter".to_string(),
            100 => "expected whitespace".to_string(),
            other => format!("[parser bug: unrecognised code {}]", other),
        },
        other => format!("[parser internal: {:?}]", other),
    }
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
            Ok((
                CompleteStr(""),
                "0.0.0.0".parse::<Ipv4Addr>().unwrap().into()
            )),
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
            Ok((
                CompleteStr(""),
                AMP::new_str_v4(Some("0.0.0.0"), None, None)
            )),
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
}
