use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::io::Read;
use std::path::Path;

use failure::Error;

pub type Inode = u32;
pub type PidMap = HashMap<Inode, InodeInfo>;

#[derive(Copy, Clone, Default)]
pub struct InodeInfo {
    pub pid: u32,
    pub fd: u32,
    process: [u8; 16],
}

pub fn walk<P: AsRef<Path>>(root: P) -> Result<(bool, PidMap), Error> {
    let mut failures = false;
    let mut ret = HashMap::with_capacity(512);
    let root = root.as_ref();
    for proc_entry in root.read_dir()? {
        let proc_entry = proc_entry?;

        let pid = match proc_entry.file_name().to_string_lossy().parse::<u32>() {
            Ok(pid) => pid,
            Err(_) => continue,
        };

        let mut name = None;

        let mut pid_path = root.to_path_buf();
        pid_path.push(proc_entry.file_name());
        let pid_path = pid_path;

        let mut fd_path = pid_path.clone();
        fd_path.push("fd");

        for fd_entry in match fd_path.read_dir() {
            Ok(dir) => dir,
            Err(_) => {
                // A process not owned by us fails here
                failures = true;
                continue;
            }
        } {
            let fd_entry = fd_entry?;
            let fd = match fd_entry.file_name().to_string_lossy().parse::<u32>() {
                Ok(fd) => fd,
                Err(_) => {
                    // not an fd number, ignore
                    continue;
                }
            };

            let inode = match fd_entry.path().read_link() {
                Ok(dest) => {
                    let dest = dest.to_string_lossy();
                    if !dest.starts_with("socket:[") || !dest.ends_with(']') {
                        // not a socket, ignore
                        continue;
                    }

                    // If we can't parse this, then we probably messed something up
                    dest["socket:[".len()..dest.len() - 1].parse()?
                }
                Err(_) => {
                    // Allowed to know about a process' files,
                    // but not allowed to view where they are?
                    failures = true;
                    continue;
                }
            };

            if name.is_none() {
                // Ew.
                let mut stat_path = pid_path.clone();
                stat_path.push("stat");
                let mut buf = [0u8; 32];
                fs::File::open(stat_path)?.read_exact(&mut buf)?;
                let start = buf
                    .iter()
                    .position(|&c| b'(' == c)
                    .ok_or_else(|| format_err!("invalid stat: ("))?
                    + 1;
                let end = buf
                    .iter()
                    .skip(start)
                    .position(|&c| b')' == c)
                    .ok_or_else(|| format_err!("invalid stat: )"))?;
                let mut name_buf = [0u8; 16];
                name_buf[..end].clone_from_slice(&buf[start..(start + end)]);
                name = Some(name_buf);
            }

            ret.insert(
                inode,
                InodeInfo {
                    pid,
                    fd,
                    process: name.unwrap(),
                },
            );
        }
    }

    Ok((failures, ret))
}

impl InodeInfo {
    // TODO: trailing nulls?
    pub fn process_name(&self) -> String {
        String::from_utf8_lossy(&self.process.to_vec()).to_string()
    }
}

impl fmt::Debug for InodeInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/fd/{}: {}", self.pid, self.fd, self.process_name())
    }
}
