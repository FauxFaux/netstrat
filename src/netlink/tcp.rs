/// Fields available as of Linux 3.2; still compatible
/// (although only through alignment weirdness)
#[repr(C)]
struct TcpInfo {
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
