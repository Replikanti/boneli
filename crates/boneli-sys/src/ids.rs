//! The single id mapping (ADR-007, D1).

use crate::error::{Error, Result};

/// The uid and gid the workload has inside its user namespace. Each maps to
/// the caller's effective uid or gid on the host through a single line
/// `<inside> <host> 1`; no other id exists inside.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ids {
    uid: u32,
    gid: u32,
}

/// `(uid_t)-1`: the "no change" value of `setresuid` and `chown`, never an id.
const NOT_AN_ID: u32 = u32::MAX;

impl Ids {
    /// Ids inside the sandbox: 0 (root, for images that need it) or the
    /// image's user. Every value but 4294967295 is valid.
    pub fn new(inside_uid: u32, inside_gid: u32) -> Result<Ids> {
        for id in [inside_uid, inside_gid] {
            if id == NOT_AN_ID {
                return Err(Error::InvalidId(id));
            }
        }
        Ok(Ids {
            uid: inside_uid,
            gid: inside_gid,
        })
    }

    /// The uid inside.
    pub fn inside_uid(&self) -> u32 {
        self.uid
    }

    /// The gid inside.
    pub fn inside_gid(&self) -> u32 {
        self.gid
    }

    /// The `uid_map` line for a host uid.
    pub fn uid_map_line(&self, host_uid: u32) -> String {
        map_line(self.uid, host_uid)
    }

    /// The `gid_map` line for a host gid.
    pub fn gid_map_line(&self, host_gid: u32) -> String {
        map_line(self.gid, host_gid)
    }
}

fn map_line(inside: u32, host: u32) -> String {
    format!("{inside} {host} 1\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inside_id_bounds() {
        for id in [0, 999, 4_294_967_294] {
            let ids = Ids::new(id, id).expect("valid id");
            assert_eq!(ids.uid_map_line(1000), format!("{id} 1000 1\n"));
            assert_eq!(ids.gid_map_line(1001), format!("{id} 1001 1\n"));
            assert_eq!((ids.inside_uid(), ids.inside_gid()), (id, id));
        }
        assert!(matches!(
            Ids::new(4_294_967_295, 0),
            Err(Error::InvalidId(4_294_967_295))
        ));
        assert!(matches!(
            Ids::new(0, 4_294_967_295),
            Err(Error::InvalidId(4_294_967_295))
        ));
    }
}
