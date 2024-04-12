//! Subuidless

use std::env::var;
use std::fs::remove_file;
use std::io::ErrorKind;
use std::os::unix::net::UnixListener;
use std::path::Path;

use anyhow::{Context, Result};

use crate::error::SyscallErrno;

#[allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
mod proto {
    include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));
}

/// Provides `SyscallError` used to attach an `Errno` to an `Error` which is then returned to the Caller
pub mod error;
/// Type Alies for `SyscallErrno` for ease of use.
pub type Error = SyscallErrno;

/// Contains `MaybeRemote` to work with the Arguments provided by Seccomp
pub mod mem;

/// Provides the `syscall!` Macro to ease the implementation of new Syscalls
pub mod syscall;
/// Helper Methods to modify the rootlesscontaine.rs xAttribute
/// <https://github.com/rootless-containers/proto>
pub mod xattr;

/// Creates the Unix Socket `subuidless.socket` at `$XDG_RUNTIME_DIR`  
/// Fails if `$XDG_RUNTIME_DIR` is not set
///
/// # Examples
/// ```ignore
/// use std::os::fd::RawFd;
/// # use std::process::{Command, Stdio};
/// # use std::thread::{JoinHandle, spawn};
/// # use anyhow::Result;
/// use libseccomp::ScmpNotifReq;
/// use sendfd::RecvWithFd;
/// use subuidless::create_socket;
///
/// fn main() -> Result<()> {
///     let listener = create_socket()?;
///     # let listener_handle: JoinHandle<Result<()>> = spawn(move || {
///     let (unix_stream, _socket_address) = listener.accept()?;
///     let mut fd: [RawFd; 1] = [0; 1];
///     unix_stream.recv_with_fd(&mut [], &mut fd)?;
///     let notif_req = ScmpNotifReq::receive(fd[0])?;
///     println!("{:?}", notif_req);
///     # Ok(())
///     # });
///     #  _ = Command::new("docker")
///     #    .args([
///     #    "run",
///     #    "--security-opt",
///     #    "seccomp=seccomp.json",
///     #    "alpine:latest",
///     #  ])
///     # .stderr(Stdio::null())
///     # .spawn();
///     # listener_handle.join().expect("Did not receive fd")
/// }
/// ```
pub fn create_socket() -> Result<UnixListener> {
    let xdg_runtime_dir =
        var("XDG_RUNTIME_DIR").context("Must specify XDG_RUNTIME_DIR for socket Path")?;
    let socket_path = Path::new(&xdg_runtime_dir).join("subuidless.socket");

    if let Err(err) = remove_file(&socket_path) {
        if err.kind() == ErrorKind::NotFound {
            Ok(())
        } else {
            Err(err)
        }?;
    }

    UnixListener::bind(socket_path).context("Could not create the unix socket")
}
