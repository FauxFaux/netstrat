use std::mem;

use netlink::diag::InetDiag;

/// Fields available as of Linux 3.2; still compatible to 4.16 (2018)
/// (although only through alignment weirdness).
#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct TcpInfo {
    state: u8,
    ca_state: u8,
    retransmits: u8,
    probes: u8,
    backoff: u8,
    options: u8,
    packed_wscale: u8,

    rto: u32,
    ato: u32,
    snd_mss: u32,
    rcv_mss: u32,
    unacked: u32,
    sacked: u32,
    lost: u32,
    retrans: u32,
    fackets: u32,

    // Times.
    last_data_sent: u32,
    _last_ack_sent: u32,
    last_data_recv: u32,
    last_ack_recv: u32,

    // Metrics.
    pmtu: u32,
    rcv_ssthresh: u32,
    rtt: u32,
    rttvar: u32,
    snd_ssthresh: u32,
    snd_cwnd: u32,
    advmss: u32,
    reordering: u32,
    rcv_rtt: u32,
    rcv_space: u32,
    total_retrans: u32,
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum State {
    Established = 1,
    SynSent = 2,
    SynRecv = 3,
    FinWait1 = 4,
    FinWait2 = 5,
    TimeClose = 6,
    Close = 7,
    CloseWait = 8,
    LastAck = 9,
    Listen = 10,
    Closing = 11,
    NewSynRecv = 12,
}

bitflags! {
    pub struct States: u16 {
        const ESTABLISHED  = (1 << State::Established as usize);
        const SYN_SENT     = (1 << State::SynSent     as usize);
        const SYN_RECV     = (1 << State::SynRecv     as usize);
        const FIN_WAIT_1   = (1 << State::FinWait1    as usize);
        const FIN_WAIT_2   = (1 << State::FinWait2    as usize);
        const TIME_CLOSE   = (1 << State::TimeClose   as usize);
        const CLOSE        = (1 << State::Close       as usize);
        const CLOSE_WAIT   = (1 << State::CloseWait   as usize);
        const LAST_ACK     = (1 << State::LastAck     as usize);
        const LISTEN       = (1 << State::Listen      as usize);
        const CLOSING      = (1 << State::Closing     as usize);
        const NEW_SYN_RECV = (1 << State::NewSynRecv  as usize);
    }
}

impl State {
    fn from_u8(val: u8) -> Option<State> {
        if val >= 1 || val <= 12 {
            // Safe so long as 'val' is in range, which is manually checked here.
            Some(unsafe { mem::transmute(val) })
        } else {
            None
        }
    }

    pub fn abbr(&self) -> &'static str {
        use self::State::*;
        #[cfg_attr(rustfmt, rustfmt_skip)]
        match *self {
            Established => "ESTABL",
            SynSent     => "SYNSNT",
            SynRecv     => "SYNRCV",
            FinWait1    => "FINWT1",
            FinWait2    => "FINWT2",
            TimeClose   => "TIMCLS",
            Close       => "CLOSE",
            CloseWait   => "CLSWAT",
            LastAck     => "LSTACK",
            Listen      => "LISTEN",
            Closing     => "CLOSIN",
            NewSynRecv  => "NEWSYN",
        }
    }
}

impl States {
    pub fn connected() -> States {
        States::ESTABLISHED | States::SYN_SENT | States::SYN_RECV | States::FIN_WAIT_1
            | States::FIN_WAIT_2 | States::CLOSE_WAIT | States::LAST_ACK | States::CLOSING
    }

    pub fn matches(&self, msg: &InetDiag) -> bool {
        if let Some(msg) = msg.tcp.and_then(|tcp| State::from_u8(tcp.state)) {
            self.contains(States::from_bits_truncate(1 << msg as usize))
        } else {
            // TODO: not TCP, or not valid?
            true
        }
    }
}

impl TcpInfo {
    pub fn state(&self) -> Option<State> {
        State::from_u8(self.state)
    }
}
