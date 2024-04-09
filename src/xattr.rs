use std::fs::File;
use std::io;

use libc::{gid_t, uid_t};
use protobuf::Message;
use xattr::FileExt;

use crate::proto::rootlesscontainers::Resource;

const XA_USER_ROOTLESSCONTAINERS: &str = "user.rootlesscontainers";

/// Modify the XA User xAttribute
/// The main purpose of this attribute is to allow for an interoperable and standardised way of emulating persistent syscalls in a rootless container (syscalls such as chown(2) which would ordinarily fail).
/// <https://github.com/rootless-containers/proto>
pub trait XaUser {
    /// Set the `XA_USER_ROOTLESSCONTAINERS` xAttribute of a file.
    /// If the uid & gid are both equal to 0 the xAttribute is removed
    ///
    /// # Examples
    ///
    /// ```
    /// use std::fs::{File};
    /// use subuidless::xattr::XaUser;
    ///
    /// fn main() -> std::io::Result<()> {
    ///     let file = File::create("/tmp/example")?;
    ///     file.set_xa_user(1000, 1000)?;
    ///     Ok(())
    /// }
    ///
    /// ```
    fn set_xa_user(&self, uid: uid_t, gid: gid_t) -> io::Result<()>;

    /// Get the `XA_USER_ROOTLESSCONTAINERS` xAttribute of a file.  
    /// If the xAttribute is not set the uid and gid returned are both 0
    ///
    /// # Examples
    ///
    /// ```
    /// use std::fs::{File};
    /// use subuidless::xattr::XaUser;
    ///
    /// fn main() -> std::io::Result<()> {
    ///     let file = File::create("/tmp/example")?;
    ///     file.set_xa_user(1000, 1000)?;
    ///     let (uid, gid) = file.get_xa_user()?;
    ///     assert_eq!(uid, 1000);
    ///     assert_eq!(gid, 1000);
    ///     Ok(())
    /// }
    ///
    /// ```
    fn get_xa_user(&self) -> io::Result<(uid_t, gid_t)>;
}

impl XaUser for File {
    fn set_xa_user(&self, uid: uid_t, gid: gid_t) -> io::Result<()> {
        if uid == 0 && gid == 0 {
            return self.remove_xattr(XA_USER_ROOTLESSCONTAINERS);
        }

        let resource = Resource {
            uid,
            gid,
            ..Default::default()
        };

        self.set_xattr(XA_USER_ROOTLESSCONTAINERS, &resource.write_to_bytes()?)
    }

    fn get_xa_user(&self) -> io::Result<(uid_t, gid_t)> {
        Ok(self
            .get_xattr(XA_USER_ROOTLESSCONTAINERS)?
            .as_deref()
            .map(Resource::parse_from_bytes)
            .map_or(Ok((0, 0)), |res| {
                res.map(|resource| (resource.uid, resource.gid))
            })?)
    }
}
