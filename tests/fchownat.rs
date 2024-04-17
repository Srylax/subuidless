use std::fs::File;
use std::os::fd::AsRawFd;

use nix::fcntl::AtFlags;
use nix::libc::{c_int, gid_t, uid_t};
use nix::unistd::{fchownat, Gid, Uid};
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

pub fn file_strategy() -> impl Strategy<Value = String> {
    Union::new(include_str!("./files.txt").lines())
}

pub fn dir_strategy() -> impl Strategy<Value = Option<String>> {
    Union::new(
        include_str!("./files.txt")
            .lines()
            .map(|line| Just(Some(line.to_string()))),
    )
    .prop_union(Union::new_weighted(vec![(10, Just(None))]))
}

pub fn id_strategy() -> impl Strategy<Value = u32> {
    let existing = Union::new_weighted((1..=11).map(|uid| (3, Just(uid))).collect::<Vec<_>>());

    let maybe_existing =
        Union::new_weighted((12..=1000).map(|uid| (2, Just(uid))).collect::<Vec<_>>());

    let union = existing.prop_union(maybe_existing).boxed();
    prop_oneof![
        1 => Just(0),
        2 => Just(0xFFFE),
    ]
    .boxed()
    .prop_union(union)
}

syscall!(
    Fchownat {
        #[proptest(strategy = "file_strategy()")]
        path: String,
        #[proptest(strategy = "dir_strategy()")]
        dir: Option<String>,
        #[proptest(strategy = "id_strategy()")]
        owner: uid_t,
        #[proptest(strategy = "id_strategy()")]
        group: gid_t,
        #[proptest(strategy = "flag_strategy()")]
        flags: i32
    },
    // Act
    self {
        let fd = self.dir.as_ref().and_then(|dir|File::open(dir).ok()).map(|file|file.as_raw_fd());
        fchownat(fd, self.path.as_str(), Some(Uid::from_raw(self.owner)), Some(Gid::from_raw(self.group)) ,AtFlags::from_bits_retain(self.flags))?;
    },
    // Assert
    test_fstatat(fstatat, (left,right): (uid_t, gid_t)) {
        prop_assert_eq!(left, right);
        prop_assert_eq!(left, right);
        Ok::<(),TestCaseError>(())
});
