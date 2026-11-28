//! Boneli adapter: the `Sandbox` port on the Linux runtime of `boneli-sys`
//! (#8, ADR-007, ADR-042).
//!
//! A pod is one user and network namespace with a container per root
//! filesystem, and the workspace crosses its boundary only in the
//! workspace format of `boneli-workspace` (ADR-010, D2): copied in when
//! the pod is created, read back by `export` and `seal`. Part 4 of #8 adds
//! the reading side, the [`tree`] module; the pod that uses it is part 5.
//!
//! - [`tree::read_file`] is `copy_out`: one regular file of the workspace,
//!   never through a symlink or a mount point.
//! - [`tree::export`] walks the workspace into the workspace format, under
//!   the tree path rule [`tree::TreeRule`] (ADR-018), with a node, a name
//!   and a byte cap.
//! - [`tree::copy_tree`] is `seal`'s copier: it streams the listed
//!   directories into a new layer directory under the same rules and caps.
//!
//! All three resolve only through `boneli_sys::fs::open_beneath`, so
//! nothing an agent planted in the tree points the runner, which holds the
//! git token, at a path outside it (ADR-042, D5).
#![doc(test(attr(forbid(unsafe_code))))]

pub mod tree;
