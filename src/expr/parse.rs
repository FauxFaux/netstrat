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
use nom::multispace0;
use nom::types::CompleteStr;

use errors::*;
use expr::AddrFilter;
use expr::AddrMaskPort;
use expr::Expression;
use expr::Input;
use expr::Op;
use netlink::tcp::States;

named!(mandatory_whitespace<CompleteStr, CompleteStr>, add_return_error!(ErrorKind::Custom(100),
    call!(multispace)
));

named!(port_input<CompleteStr, Input>,
    alt_complete!(
        tag!("sport") => { |_| Input::SrcPort } |
        tag!("dport") => { |_| Input::DstPort } |
        tag!("port")  => { |_| Input::EitherPort }
));

named!(addr_input<CompleteStr, Input>,
    alt_complete!(
        tag!("src")     => { |_| Input::Src } |
        tag!("source")  => { |_| Input::Src } |
        tag!("dst")     => { |_| Input::Dst } |
        tag!("dest")    => { |_| Input::Dst } |
        tag!("address") => { |_| Input::EitherAddr } |
        tag!("addr")    => { |_| Input::EitherAddr }
));

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

named!(state<CompleteStr, States>, add_return_error!(ErrorKind::Custom(3),
    alt_complete!(
        tag!("connected")    => { |_| States::connected() } |
        tag!("synchronised") => { |_| States::synchronised() } |
        tag!("bucket")       => { |_| States::bucket() } |
        tag!("big")          => { |_| States::big() } |
        tag!("established")  => { |_| States::ESTABLISHED } |
        tag!("syn-sent")     => { |_| States::SYN_SENT } |
        tag!("syn-recv")     => { |_| States::SYN_RECV } |
        tag!("fin-wait-1")   => { |_| States::FIN_WAIT_1 } |
        tag!("fin-wait-2")   => { |_| States::FIN_WAIT_2 } |
        tag!("time-wait")    => { |_| States::TIME_WAIT } |
        tag!("closed")       => { |_| States::CLOSED } |
        tag!("close-wait")   => { |_| States::CLOSE_WAIT } |
        tag!("last-ack")     => { |_| States::LAST_ACK } |
        tag!("listening")    => { |_| States::LISTEN } |
        tag!("closing")      => { |_| States::CLOSING }
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

named!(port_number<CompleteStr, u16>,
    alt_complete!(
        map_res!(take_while1_s!(digit), parse_u16) |
        tag!("*") => { |_| 0 }
));

named!(port<CompleteStr, u16>, preceded!(complete!(tag!(":")), port_number));

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
            return_error!(ErrorKind::Custom(2400), alt_complete!(
                v4addr |
                v6addr
            )),
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

named!(op_port<CompleteStr, (Op, u16)>,
    do_parse!(
        // TODO: this accepts 'port80' which I'm not happy with
        op: opt!(op) >>
        call!(multispace0) >>
        opt!(tag!(":")) >>
        port: port_number >>
        ( ( op.unwrap_or(Op::Eq), port ))
    )
);

named!(port_expr<CompleteStr, Expression>,
    do_parse!(
        input: port_input >>
        call!(multispace0) >>
        op_port: op_port >>
        (
            Expression::Addr(AddrFilter {
                input,
                op: op_port.0,
                addr: AddrMaskPort { addr: None, mask: None, port: Some(op_port.1) }
            })
        )
    )
);

named!(op_addr<CompleteStr, (Op, AddrMaskPort)>,
    do_parse!(
        op: op >>
        call!(multispace0) >>
        addr: amp_addr_opt_opt >>
        ( (op, addr) )
));

named!(whole_addr_expr<CompleteStr, Expression>,
    do_parse!(
        input: addr_input >>
        call!(multispace0) >>
        op_addr: op_addr >>
        ( Expression::Addr(AddrFilter { input, op: op_addr.0, addr: op_addr.1 }) )
    )
);

named!(addr_expr<CompleteStr, Expression>, add_return_error!(ErrorKind::Custom(60),
    alt_complete!(
        whole_addr_expr |
        port_expr
)));

named!(state_expr<CompleteStr, Expression>, add_return_error!(ErrorKind::Custom(61),
    do_parse!(
        tag!("state") >>
        mandatory_whitespace >>
        state: return_error!(ErrorKind::Custom(6100), state) >>
        ( Expression::State(state) )
)));

named!(not_expr<CompleteStr, Expression>, add_return_error!(ErrorKind::Custom(70),
    do_parse!(
        tag!("not") >>
        call!(multispace) >>
        exp: single_expr >>
        ( Expression::Not(Box::new(exp)) )
)));

named!(single_expr<CompleteStr, Expression>, add_return_error!(ErrorKind::Custom(71),
    alt_complete!(
        delimited!(
            tag!("("),
            return_error!(ErrorKind::Custom(7100), root),
            tag!(")")
        ) |
        not_expr |
        addr_expr |
        state_expr
)));

named!(root<CompleteStr, Expression>, add_return_error!(ErrorKind::Custom(72),
    ors
));

named!(ors<CompleteStr, Expression>, add_return_error!(ErrorKind::Custom(73),
    do_parse!(
        list: separated_nonempty_list_complete!(
            // TODO: whitespace
            tag!(" or "),
            return_error!(ErrorKind::Custom(7300), ands)) >>
        ( Expression::AnyOf(list) )
)));

named!(ands<CompleteStr, Expression>, add_return_error!(ErrorKind::Custom(74),
    do_parse!(
        list: separated_nonempty_list_complete!(
            // TODO: whitespace
            tag!(" and "),
            return_error!(ErrorKind::Custom(7400), single_expr)) >>
        ( Expression::AllOf(list) )
)));

pub fn parse(input: &str) -> Result<Expression> {
    match root(CompleteStr(input)) {
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
                "failed to parse {}, near ... {} ...",
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
            2400 => "bracketed address".to_string(),
            40 => "address with optional mask/port".to_string(),
            41 => ":port without address".to_string(),
            42 => "address/mask:port (hint: v6 addresses should be [bracketed])".to_string(),
            60 => "address filter".to_string(),
            6000 => "'address' argument".to_string(),
            61 => "state filter".to_string(),
            6100 => "'state' argument ".to_string(),
            71 => "expression; expected '(', 'state' or INPUT".to_string(),
            7100 => "nested expression".to_string(),
            72 => "root".to_string(),
            73 => "any-of; expected expression or 'or'".to_string(),
            7300 => "nested any-of expression".to_string(),
            74 => "all-of; expected expression or 'and'".to_string(),
            7400 => "nested all-of expression".to_string(),
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
                    input: Input::SrcPort,
                    op: Op::Eq,
                    addr: AMP::new_str_v4(None, None, Some(80)),
                })
            )),
            addr_expr(CompleteStr("sport eq :80"))
        );
    }
}
