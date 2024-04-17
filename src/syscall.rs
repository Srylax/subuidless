use libseccomp::{ScmpFd, ScmpNotifReq, ScmpSyscall};

mod fchownat;
mod fstatat;
/// Syscall trait for the `inventory` crate
/// All Implementation of this trait get collected into a `HashMap` where `ScmpSyscall` is the key
/// This allows for `O(n)` access when a new `ScmpNotifReq` is received.
pub trait Syscall: Sync {
    /// Main function of the syscall. Everything the syscall does, happens here
    fn execute(&self, req: ScmpNotifReq, fd: ScmpFd) -> Result<i64, crate::Error>;

    /// Get the associated `ScmpSyscall` - used to build the `HashMap`
    fn get_syscall(&self) -> anyhow::Result<ScmpSyscall>;
}

/// Implements the `Syscall` Trait to ease the implementation for a new Syscall
/// Transforms all Arguments to the target type. This helps to avoid TOCTOU style attacks by forcing the Implementation to read all Arguments first.
#[macro_export]
macro_rules! syscall {
    ($name:ident {
    $($arg:ident: $arg_type:ty),*
    }, $self:ident $body:block) => {
        pub struct $name;

        struct SyscallData {
            #[allow(unused)]
            req: libseccomp::ScmpNotifReq,
            #[allow(unused)]
            fd: libseccomp::ScmpFd,
            $(
            $arg: $arg_type,
            )*
        }

        impl SyscallData {
            fn new(req: libseccomp::ScmpNotifReq, fd: libseccomp::ScmpFd, $($arg: $arg_type),*) -> Result<Self, $crate::Error> {
                Ok(Self {
                    req,
                    fd,
                    $($arg),*
                })
            }
            fn execute_internal($self: Self) -> Result<i64, $crate::Error> $body
        }
        #[allow(clippy::semicolon_outside_block)]
        impl $crate::syscall::Syscall for $name {
            fn execute(&self, req: libseccomp::ScmpNotifReq, fd: libseccomp::ScmpFd) -> Result<i64, $crate::Error> {
                $crate::arg!(0_usize, req, fd, $($arg: $arg_type),*);
                SyscallData::new(req, fd, $($arg),*)?.execute_internal()
            }
            fn get_syscall(&self) -> anyhow::Result<libseccomp::ScmpSyscall> {
                Ok(libseccomp::ScmpSyscall::from_name(&stringify!($name).to_lowercase())?)
            }
        }

        inventory::submit! {
            &$name as &dyn $crate::syscall::Syscall
        }
    };
}

/// Constructs a `MaybeRemote` and tries to Transform it into the target type
/// Uses recursive Macro calls to access attributes in the `args: [u64;6]` array
#[macro_export]
macro_rules! arg {
    ($idx:expr, $req:ident, $fd:ident, $var:ident: $var_type:ty) => {
        let $var: $var_type = $crate::mem::MaybeRemote::new(
            nix::unistd::Pid::from_raw(i32::try_from($req.pid).map_err($crate::error::attach(nix::errno::Errno::EINVAL))?),
            $req.data.args[$idx],
            $fd,
            $req.id
        ).try_into()?;
    };

    ( $idx:expr, $req:ident, $fd:ident, $var:ident: $var_type:ty, $($t_var:ident: $t_var_type:ty),*) => {
        $crate::arg!($idx, $req, $fd, $var: $var_type);
        $crate::arg!($idx + 1_usize,  $req, $fd, $($t_var: $t_var_type),*);
    };
}
inventory::collect!(&'static dyn Syscall);
