//! Modify the XA User xAttribute
//! The main purpose of this attribute is to allow for an interoperable and standardised way of emulating persistent syscalls in a rootless container (syscalls such as chown(2) which would ordinarily fail).
//! <https://github.com/rootless-containers/proto>
use std::mem::size_of;

use nix::errno::Errno;
use nix::libc::{gid_t, uid_t};
use protobuf::Message;
use rustix::io as rio;
use rustix::{fs, path};

use crate::error::attach;
use crate::proto::rootlesscontainers::Resource;

const XA_USER_ROOTLESSCONTAINERS: &str = "user.rootlesscontainers";

/// Set the `XA_USER_ROOTLESSCONTAINERS` xAttribute of a file.
/// If the uid & gid are both equal to 0 the xAttribute is removed
///
/// # Examples
///
/// ```
/// # use anyhow::Result;
/// use std::fs::File;
/// use subuidless::xattr::set_xa_user;
///
/// fn main() -> Result<()> {
///     let _file = File::create("/tmp/example")?;
///     set_xa_user("/tmp/example", false, 1000, 1000)?;
///     Ok(())
/// }
/// ```
pub fn set_xa_user<P: path::Arg + Clone>(
    path: P,
    follow: bool,
    uid: uid_t,
    gid: gid_t,
) -> Result<(), crate::Error> {
    let removexattr = if follow {
        fs::removexattr
    } else {
        fs::lremovexattr
    };

    if uid == 0 && gid == 0 {
        removexattr(path.clone(), XA_USER_ROOTLESSCONTAINERS)?;
    }
    let resource = Resource {
        uid,
        gid,
        ..Default::default()
    };

    let setxattr = if follow { fs::setxattr } else { fs::lsetxattr };

    setxattr(
        path,
        XA_USER_ROOTLESSCONTAINERS,
        &resource.write_to_bytes().map_err(attach(Errno::ENOTSUP))?,
        fs::XattrFlags::empty(),
    )?;

    Ok(())
}

/// Get the `XA_USER_ROOTLESSCONTAINERS` xAttribute of a file.
/// If the xAttribute is not set the uid and gid returned are both 0
///
/// # Examples
///
/// ```
/// # use anyhow::Result;
/// use std::fs::File;
/// use subuidless::xattr::get_xa_user;
/// use subuidless::xattr::set_xa_user;
///
/// fn main() -> Result<()> {
///     let _file = File::create("/tmp/example")?;
///     set_xa_user("/tmp/example", false, 1000, 1000)?;
///     let (uid, gid) = get_xa_user("/tmp/example", false)?;
///     assert_eq!(uid, 1000);
///     assert_eq!(gid, 1000);
///     Ok(())
/// }
/// ```
pub fn get_xa_user<P: path::Arg + Clone>(
    path: P,
    follow: bool,
) -> Result<(uid_t, gid_t), crate::Error> {
    let mut buf = vec![0; size_of::<Resource>()];

    let getxattr = if follow { fs::getxattr } else { fs::lgetxattr };

    let size = match getxattr(path, XA_USER_ROOTLESSCONTAINERS, &mut buf) {
        Ok(size) => Ok(size),
        Err(err) => {
            if err == rio::Errno::NODATA {
                return Ok((0, 0));
            }
            Err(err)
        }
    }?;

    buf.truncate(size);
    buf.shrink_to_fit();

    let resource = Resource::parse_from_bytes(&buf).map_err(attach(Errno::ENOTSUP))?;

    Ok((resource.uid, resource.gid))
}
