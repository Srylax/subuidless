use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::PathBuf;

use nix::fcntl::{openat, OFlag};
use nix::sys::stat::Mode;

use crate::syscall;

syscall!(Fchownat {
    dirfd: Option<File>,
    pathname: PathBuf,
    flags: OFlag,
    mode: Mode
}, self {

    openat(self.dirfd.map(|file|file.as_raw_fd()), &self.pathname, self.flags, self.mode)?;
    Ok(0)
});
