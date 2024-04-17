//!
#[cfg(test)]
mod fchownat;
#[cfg(test)]
mod newfstatat;

#[cfg(feature = "executor")]
subuidless_test::create_docker!(
    "subuidless",
    "subuidless/src",
    "subuidless/Cargo.toml",
    "subuidless/build.rs",
    "subuidless/tests"
);

#[cfg(not(test))]
subuidless_test::executor!();
