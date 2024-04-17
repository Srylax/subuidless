use std::fs::File;
use std::path::{Path, PathBuf};

use nix::fcntl::AtFlags;
use nix::libc::{gid_t, uid_t};
use nix::unistd::chdir;

use crate::syscall;
use crate::xattr::set_xa_user;

syscall!(Fchownat {
    _dirfd: Option<File>,
    pathname: PathBuf,
    owner: uid_t,
    group: gid_t,
    flags: AtFlags
},
    self {
        if !self.pathname.is_absolute() {
            chdir(Path::new(&format!("/proc/{}/cwd", self.req.pid)))?;
        }

        let follow = !AtFlags::contains(&self.flags, AtFlags::AT_SYMLINK_NOFOLLOW);

        let _err = set_xa_user(&self.pathname, follow, self.owner, self.group);
        Ok(0)
});
