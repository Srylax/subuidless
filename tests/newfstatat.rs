use std::fs::File;
use std::os::fd::AsRawFd;

use nix::fcntl::AtFlags;
use nix::libc::{c_int, gid_t, uid_t};
use nix::sys::stat::fstatat;
use proptest::prelude::*;
use proptest::strategy::Union;
use subuidless_test::syscall;

pub fn flag_strategy() -> BoxedStrategy<c_int> {
    prop_oneof![
        10 => Just(AtFlags::empty().bits()),
        1 => Just(AtFlags::AT_SYMLINK_FOLLOW.bits()),
        1 => Just(AtFlags::AT_SYMLINK_NOFOLLOW.bits()),
        1 => Just(AtFlags::AT_NO_AUTOMOUNT.bits()),
        1 => Just(AtFlags::AT_EMPTY_PATH.bits()),
        1 => Just(AtFlags::AT_EACCESS.bits())
    ]
    .boxed()
}

#[allow(clippy::large_include_file)]
pub fn file_strategy() -> impl Strategy<Value = String> {
    Union::new(include_str!("./files.txt").lines())
}
#[allow(clippy::large_include_file)]
pub fn dir_strategy() -> impl Strategy<Value = Option<String>> {
    Union::new(
        include_str!("./files.txt")
            .lines()
            .map(|line| Just(Some(line.to_owned()))),
    )
    .prop_union(Union::new_weighted(vec![(10, Just(None))]))
}

syscall!(
    Fstatat {
        #[proptest(strategy = "file_strategy()")]
        path: String,
        #[proptest(strategy = "dir_strategy()")]
        dir: Option<String>,
        #[proptest(strategy = "flag_strategy()")]
        flags: i32
    },
    // Act
    self {
        let fd = self.dir.as_ref().and_then(|dir|File::open(dir).ok()).map(|file|file.as_raw_fd());
        let stat = fstatat(fd, self.path.as_str(), AtFlags::from_bits_retain(self.flags))?;
        (stat.st_uid,stat.st_gid)
    },
    // Assert
    test_fstatat(fstatat, (left,right): (uid_t, gid_t)) {
        prop_assert_eq!(left, right);
        prop_assert_eq!(left, right);
        Ok::<(),TestCaseError>(())
});
