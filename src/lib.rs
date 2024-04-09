//! Subuidless

#[allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
mod proto {
    include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));
}

/// Helper Methods to modify the rootlesscontaine.rs xAttribute
/// <https://github.com/rootless-containers/proto>
pub mod xattr;