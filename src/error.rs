use std::ffi::c_int;

use nix::errno::Errno;
use rustix::io as rio;
use thiserror::Error;

/// Wraps existing Errors with an `Errno`
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SyscallErrno {
    /// Errors from the nix crate do not need to be wrapped
    #[error(transparent)]
    NixError(#[from] nix::Error),
    /// Errors from the rustix crate do not need to be wrapped
    #[error(transparent)]
    RustixError(#[from] rio::Errno),
    /// use `anyhow` to capture a wide variety of Errors
    #[error("{1}")]
    Anyhow(nix::Error, #[source] anyhow::Error),
}

impl From<SyscallErrno> for c_int {
    #[allow(clippy::as_conversions)]
    fn from(value: SyscallErrno) -> Self {
        match value {
            SyscallErrno::NixError(err) => err as i32,
            SyscallErrno::Anyhow(errno, _err) => errno as i32,
            SyscallErrno::RustixError(err) => err.raw_os_error(),
        }
    }
}

/// Curry that allows to "attach" an `Errno`, in a `map_err`,to any `Error` that is transformable into `anyhow::Error`
/// # Examples
/// ```
/// use anyhow::anyhow;
/// use nix::errno::Errno;
/// use subuidless::error::attach;
///
/// fn execute_syscall() -> Result<(), subuidless::Error> {
///     Err(anyhow!("Ordinary Error")).map_err(attach(Errno::EINVAL))
/// }
///
/// fn main() {
///     let err = execute_syscall().unwrap_err();
///     assert_eq!(i32::from(err), Errno::EINVAL as i32)
/// }
/// ```
pub fn attach<T: Into<anyhow::Error>>(errno: Errno) -> impl FnOnce(T) -> SyscallErrno {
    move |err| SyscallErrno::Anyhow(errno, err.into())
}
