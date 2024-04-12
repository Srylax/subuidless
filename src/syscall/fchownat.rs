use std::fs::File;
use std::path::PathBuf;

use nix::fcntl::AtFlags;
use nix::libc::{gid_t, uid_t};

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
    let follow = !AtFlags::contains(&self.flags, AtFlags::AT_SYMLINK_NOFOLLOW);

    set_xa_user(&self.pathname, follow, self.owner, self.group)?;
    Ok(0)
});
