//! Subuidless

use std::env::var;
use std::fs::{remove_file, File};
use std::io::ErrorKind;
use std::marker::PhantomData;
use std::mem::size_of;
use std::ops::Deref;
use std::os::unix::net::UnixListener;
use std::os::unix::prelude::FileExt;
use std::path::{Path, PathBuf};
use std::slice;

use anyhow::{anyhow, Context, Result};
use libseccomp::{notify_id_valid, ScmpFd};
use nix::fcntl::AtFlags;
use nix::libc::{c_int, stat};
use nix::unistd::Pid;

const PATH_MAX: usize = 4096;
#[allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
mod proto {
    include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));
}

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

#[derive(Copy, Clone)]
/// Newtype Pattern to represent the values provided by Seccomp
/// This allows for the implementation of more rust idiomatic conversions of stack values
/// # Examples
/// ```
/// # use anyhow::Result;
/// use nix::fcntl::AtFlags;
/// use subuidless::ScmpArg;
///
/// fn main() -> Result<()> {
///     let arg: ScmpArg = 4096.into();
///     let arg: AtFlags = arg.try_into()?;
///     assert_eq!(AtFlags::AT_EMPTY_PATH, arg);
///     Ok(())
/// }
/// ```
pub struct ScmpArg(u64);

impl From<u64> for ScmpArg {
    fn from(value: u64) -> Self {
        Self(value)
    }
}
impl Deref for ScmpArg {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<ScmpArg> for AtFlags {
    type Error = anyhow::Error;

    fn try_from(value: ScmpArg) -> Result<Self, Self::Error> {
        AtFlags::from_bits(c_int::try_from(*value)?).ok_or(anyhow!("Invalid AtFlag"))
    }
}

/// Represents a pointer to a struct that is in the Callers memory
struct RemoteStruct<T: Plain> {
    pid: Pid,
    pointer: ScmpArg,
    fd: ScmpFd,
    id: u64,
    remote_type: PhantomData<T>,
}

impl<T: Plain> RemoteStruct<T> {
    #[must_use]
    fn new(pid: Pid, pointer: ScmpArg, fd: ScmpFd, id: u64) -> Self {
        Self {
            pid,
            pointer,
            fd,
            id,
            remote_type: PhantomData,
        }
    }
    #[allow(clippy::needless_pass_by_value)] // We want to drop T after writing it
    fn write(self, mem: T) -> Result<()> {
        #[allow(
            unsafe_code,
            clippy::as_conversions,
            clippy::ptr_as_ptr,
            clippy::borrow_as_ptr
        )]
        // SAFETY:
        // Safe only if all the Safety requirements of the Trait are respected
        let mem = unsafe { slice::from_raw_parts(&mem as *const T as *const u8, size_of::<T>()) };

        let file = File::open(format!("/proc/{}/mem", self.pid))?;
        notify_id_valid(self.fd, self.id)?;
        file.write_at(mem, *self.pointer)?;
        notify_id_valid(self.fd, self.id)?;

        Ok(())
    }
}

/// Represents a String living in the memory of another Process  
/// When converting to a String with `String::try_from()` the remote Process memory is being read.  
/// To mitigate TOCTOU style attacks `notify_id_valid` is used *after* the remote memory is read <https://wiki.sei.cmu.edu/confluence/display/c/FIO45-C.+Avoid+TOCTOU+race+conditions+while+accessing+files>
struct RemotePath {
    pid: Pid,
    pointer: ScmpArg,
    fd: ScmpFd,
    id: u64,
}

impl TryFrom<RemotePath> for PathBuf {
    type Error = anyhow::Error;
    fn try_from(value: RemotePath) -> Result<Self, Self::Error> {
        let file = File::open(format!("/proc/{}/mem", value.pid))?;
        notify_id_valid(value.fd, value.id)?;

        let mut data = [0; PATH_MAX];
        file.read_at(&mut data, *value.pointer)?;
        notify_id_valid(value.fd, value.id)?;

        // Get null terminator
        let index_null = data
            .iter()
            .position(|&x| x == 0)
            .context("Could not find the null terminator")?;

        let string = data
            .get(..index_null)
            .ok_or(anyhow!("index_null somehow greater than data slice"))?
            .to_vec();

        Ok(PathBuf::from(String::from_utf8(string)?))
    }
}

#[allow(unsafe_code)]
/// `Plain` old data
///
///
/// # Safety
/// See safety of `slice::from_raw_parts` and <https://doc.rust-lang.org/nomicon/transmutes.html> and <https://wiki.sei.cmu.edu/confluence/display/c/DCL39-C.+Avoid+information+leakage+when+passing+a+structure+across+a+trust+boundary>
/// * `Self` must not contain any Form of padding
/// * `Self` must be `#[repr(C)]`
/// * If written to another Process, they must share the same Architecture
unsafe trait Plain: Sized {}

#[allow(unsafe_code)]
/// SAFETY:
/// `libc::stat` is a `libc` `repr(C)` struct that contain no Padding and is even written from C code.
/// Because there is no Constructor and the padding is private there should be no situation where it would be possible to create `stat` in safe Rust.
unsafe impl Plain for stat {}
