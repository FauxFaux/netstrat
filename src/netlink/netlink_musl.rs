use libc::c_int;

const NLM_F_ROOT: c_int = 0x100;
const NLM_F_MATCH: c_int = 0x200;
pub const NLM_F_DUMP: c_int = NLM_F_ROOT | NLM_F_MATCH;
pub const NLM_F_REQUEST: c_int = 1;
pub const NETLINK_INET_DIAG: c_int = 4;
