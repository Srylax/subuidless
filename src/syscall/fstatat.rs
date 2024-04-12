use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::PathBuf;

use nix::fcntl::AtFlags;
use nix::sys::stat::{fstatat, FileStat};

use crate::mem::RemoteStruct;
use crate::syscall;
use crate::xattr::get_xa_user;

syscall!(Newfstatat {
    dirfd: Option<File>,
    pathname: PathBuf,
    remote_stat: RemoteStruct<FileStat>,
    flags: AtFlags
},
self {
    let follow = !AtFlags::contains(&self.flags, AtFlags::AT_SYMLINK_NOFOLLOW);

    let mut stat = fstatat(self.dirfd.map(|file|file.as_raw_fd()), &self.pathname, self.flags)?;

    if let Ok((uid,gid)) = get_xa_user(&self.pathname, follow) {
        stat.st_uid = uid;
        stat.st_gid = gid;
    }

    self.remote_stat.write(stat)?;
    Ok(0)
});
