//! The files space as a folder. What a change to a folder means is here on
//! every platform; showing one is not, and lives in `fuse` on Linux.

pub mod commit;
pub mod local;
pub mod tree;

#[cfg(feature = "mount")]
mod fuse;
#[cfg(feature = "mount")]
pub mod onefs;
#[cfg(feature = "mount")]
pub mod ops;
#[cfg(feature = "mount")]
pub use fuse::*;

#[cfg(not(feature = "mount"))]
mod none;
#[cfg(not(feature = "mount"))]
pub use none::*;
