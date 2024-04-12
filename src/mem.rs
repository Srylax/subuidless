use std::convert::TryFrom;
use std::ffi::c_int;
use std::fs::{File, OpenOptions};
use std::marker::PhantomData;
use std::mem::size_of;
use std::os::unix::prelude::FileExt;
use std::path::PathBuf;
use std::slice;

use anyhow::Context;
use libseccomp::{notify_id_valid, ScmpFd};
use nix::errno::Errno;
use nix::fcntl::{AtFlags, OFlag};
use nix::libc::{mode_t, stat};
use nix::sys::stat::Mode;
use nix::unistd::Pid;

use crate::error::attach;

const PATH_MAX: usize = 4096;

#[derive(Copy, Clone, Debug)]
/// Newtype for values provided in the `args: [u64;6]` array from Seccomp
/// Int values like Flags can be used instantly whereas values like Strings need to be read form the callers memory
pub struct MaybeRemote {
    pid: Pid,
    pointer: u64,
    fd: ScmpFd,
    id: u64,
}

impl MaybeRemote {
    /// Create a new `MaybeRemote`
    #[must_use]
    pub fn new(pid: Pid, pointer: u64, fd: ScmpFd, id: u64) -> Self {
        Self {
            pid,
            pointer,
            fd,
            id,
        }
    }
}

impl TryFrom<MaybeRemote> for u32 {
    type Error = crate::Error;

    fn try_from(value: MaybeRemote) -> Result<Self, Self::Error> {
        u32::try_from(value.pointer).map_err(attach(Errno::EINVAL))
    }
}

impl TryFrom<MaybeRemote> for AtFlags {
    type Error = crate::Error;

    fn try_from(value: MaybeRemote) -> Result<Self, Self::Error> {
        AtFlags::from_bits(c_int::try_from(value.pointer).map_err(attach(Errno::EINVAL))?)
            .context("Could not convert to bits")
            .map_err(attach(Errno::EINVAL))
    }
}

impl TryFrom<MaybeRemote> for OFlag {
    type Error = crate::Error;

    fn try_from(value: MaybeRemote) -> Result<Self, Self::Error> {
        OFlag::from_bits(c_int::try_from(value.pointer).map_err(attach(Errno::EINVAL))?)
            .context("Could not convert to bits")
            .map_err(attach(Errno::EINVAL))
    }
}

impl TryFrom<MaybeRemote> for Mode {
    type Error = crate::Error;

    fn try_from(value: MaybeRemote) -> Result<Self, Self::Error> {
        Mode::from_bits(mode_t::try_from(value.pointer).map_err(attach(Errno::EINVAL))?)
            .context("Could not convert to bits")
            .map_err(attach(Errno::EINVAL))
    }
}

impl TryFrom<MaybeRemote> for Option<File> {
    type Error = crate::Error;

    fn try_from(value: MaybeRemote) -> Result<Self, Self::Error> {
        let Ok(fd) = i32::try_from(value.pointer) else {
            return Ok(None);
        };
        let file =
            File::open(format!("/proc/{}/fd/{}", value.pid, fd)).map_err(attach(Errno::EBADFD))?;
        notify_id_valid(value.fd, value.id).map_err(attach(Errno::EPERM))?;
        Ok(Some(file))
    }
}

/// Represents a String living in the memory of another Process  
/// When converting to a String with `String::try_from()` the remote Process memory is being read.  
/// To mitigate TOCTOU style attacks `notify_id_valid` is used *after* the remote memory is read <https://wiki.sei.cmu.edu/confluence/display/c/FIO45-C.+Avoid+TOCTOU+race+conditions+while+accessing+files>
impl TryFrom<MaybeRemote> for PathBuf {
    type Error = crate::Error;

    fn try_from(value: MaybeRemote) -> Result<Self, Self::Error> {
        let file = File::open(format!("/proc/{}/mem", value.pid)).map_err(attach(Errno::EFAULT))?;

        notify_id_valid(value.fd, value.id).map_err(attach(Errno::EPERM))?;

        let mut data = [0; PATH_MAX];
        file.read_at(&mut data, value.pointer)
            .map_err(attach(Errno::EFAULT))?;
        notify_id_valid(value.fd, value.id).map_err(attach(Errno::EPERM))?;

        // Get null terminator
        let index_null = data
            .iter()
            .position(|&x| x == 0)
            .context("Could not find the null terminator")
            .map_err(attach(Errno::ENAMETOOLONG))?;

        let string = data
            .get(..index_null)
            .context("index_null somehow greater than data slice")
            .map_err(attach(Errno::ENAMETOOLONG))?
            .to_vec();

        Ok(PathBuf::from(
            String::from_utf8(string).map_err(attach(Errno::ENOENT))?,
        ))
    }
}

impl<T: Plain> TryFrom<MaybeRemote> for RemoteStruct<T> {
    type Error = crate::Error;

    fn try_from(value: MaybeRemote) -> Result<Self, Self::Error> {
        Ok(RemoteStruct {
            data: value,
            remote_type: PhantomData,
        })
    }
}

/// Represents a pointer to a struct that is in the Callers memory
pub struct RemoteStruct<T: Plain> {
    data: MaybeRemote,
    remote_type: PhantomData<T>,
}

impl<T: Plain> RemoteStruct<T> {
    #[allow(clippy::needless_pass_by_value)] // We want to drop T after writing it
    pub(crate) fn write(self, mem: T) -> Result<(), crate::Error> {
        #[allow(
            unsafe_code,
            clippy::as_conversions,
            clippy::ptr_as_ptr,
            clippy::borrow_as_ptr
        )]
        // SAFETY:
        // Safe only if all the Safety requirements of the Trait are respected
        let mem = unsafe { slice::from_raw_parts(&mem as *const T as *const u8, size_of::<T>()) };

        let file = OpenOptions::new()
            .write(true)
            .open(format!("/proc/{}/mem", self.data.pid))
            .map_err(attach(Errno::EFAULT))?;
        notify_id_valid(self.data.fd, self.data.id).map_err(attach(Errno::EPERM))?;
        file.write_at(mem, self.data.pointer)
            .map_err(attach(Errno::EFAULT))?;
        notify_id_valid(self.data.fd, self.data.id).map_err(attach(Errno::EPERM))?;

        Ok(())
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
pub unsafe trait Plain: Sized {}

#[allow(unsafe_code)]
/// SAFETY:
/// `libc::stat` is a `libc` `repr(C)` struct that contain no Padding and is even written from C code.
/// Because there is no Constructor and the padding is private there should be no situation where it would be possible to create `stat` in safe Rust.
unsafe impl Plain for stat {}
