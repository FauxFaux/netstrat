error_chain! {
    foreign_links {
        Io(::std::io::Error);
        Nix(::nix::Error);
        PIE(::std::num::ParseIntError);
    }
}
