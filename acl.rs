//! Access lists and the decision they feed (docs/architecture/access.md).
//!
//! An object has an owner, a group, a mode (`rwx` for owner, group, other)
//! and perhaps an access list: entries `(user | group) -> rights`, only
//! permissions (nothing denies). What a caller may do is the union of
//! what the mode's class gives, what every entry that names the caller's
//! user or group gives, and -- for the owner -- `manage`. An administrator
//! (`fs.admin`) may do all. The same function decides in the server and
//! explains in `access explain`, so the explanation is the rule that
//! decided.

use crate::{O_MANAGE, O_READ, O_WRITE, O_WRITE_ATTR};
use core::fmt::Write;

/// Rights of an entry.
pub const ACL_READ: u32 = 1 << 0;
pub const ACL_WRITE: u32 = 1 << 1;
/// Run a program (not looked at by um-vfs: the program loader's).
pub const ACL_RUN: u32 = 1 << 2;
/// Change rights and owner, the volume's management.
pub const ACL_MANAGE: u32 = 1 << 3;
pub const ACL_ALL: u32 = ACL_READ | ACL_WRITE | ACL_RUN | ACL_MANAGE;

/// `AclEntry::kind`: `id` is a user (uid) or a group (gid).
pub const ACL_USER: u8 = 1;
pub const ACL_GROUP: u8 = 2;

/// Most entries of one list.
pub const ACL_MAX: usize = 64;

/// One entry, as stored and as it travels: 12 bytes.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct AclEntry {
    pub kind: u8,
    pub _pad: [u8; 3],
    pub id: u32,
    pub rights: u32,
}

pub const ACL_ENTRY_SIZE: usize = core::mem::size_of::<AclEntry>();

impl AclEntry {
    pub const fn user(uid: u32, rights: u32) -> AclEntry {
        AclEntry {
            kind: ACL_USER,
            _pad: [0; 3],
            id: uid,
            rights,
        }
    }
    pub const fn group(gid: u32, rights: u32) -> AclEntry {
        AclEntry {
            kind: ACL_GROUP,
            _pad: [0; 3],
            id: gid,
            rights,
        }
    }
    pub fn to_bytes(&self) -> [u8; ACL_ENTRY_SIZE] {
        let mut b = [0u8; ACL_ENTRY_SIZE];
        b[0] = self.kind;
        b[4..8].copy_from_slice(&self.id.to_le_bytes());
        b[8..12].copy_from_slice(&self.rights.to_le_bytes());
        b
    }
    pub fn from_bytes(b: &[u8]) -> AclEntry {
        AclEntry {
            kind: b[0],
            _pad: [0; 3],
            id: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
            rights: u32::from_le_bytes([b[8], b[9], b[10], b[11]]),
        }
    }
}

/// The entries of a stored or transmitted list (a trailing part that is
/// not a whole entry is not one).
pub fn parse(bytes: &[u8]) -> impl Iterator<Item = AclEntry> + '_ {
    bytes
        .as_chunks::<ACL_ENTRY_SIZE>()
        .0
        .iter()
        .map(|c| AclEntry::from_bytes(c))
}

/// Is the list one to store: known kinds and rights, no entry twice, at
/// most `ACL_MAX`.
pub fn valid(list: &[AclEntry]) -> bool {
    list.len() <= ACL_MAX
        && list.iter().enumerate().all(|(i, e)| {
            matches!(e.kind, ACL_USER | ACL_GROUP)
                && e.rights & !ACL_ALL == 0
                && e.rights != 0
                && !list[..i].iter().any(|o| o.kind == e.kind && o.id == e.id)
        })
}

/// Who asks.
#[derive(Copy, Clone, Debug)]
pub struct Who {
    pub uid: u32,
    pub gid: u32,
    /// Holds `fs.admin`.
    pub admin: bool,
}

/// The parts of an object's attributes the decision uses.
#[derive(Copy, Clone, Debug)]
pub struct Subject {
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
}

/// The `ACL_*` rights `access` (`O_*` bits) asks for.
pub const fn wanted(access: u64) -> u32 {
    (if access & O_READ != 0 { ACL_READ } else { 0 })
        | (if access & O_WRITE != 0 { ACL_WRITE } else { 0 })
        | (if access & (O_WRITE_ATTR | O_MANAGE) != 0 {
            ACL_MANAGE
        } else {
            0
        })
}

/// What decided.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Class {
    Owner,
    Group,
    Other,
}

/// Every right the caller has on the object, and where each comes from.
#[derive(Copy, Clone, Debug)]
pub struct Rights {
    pub admin: bool,
    /// The class of the mode that applies, and the rights it gives.
    pub class: Class,
    pub by_mode: u32,
    /// The rights entries of the list give (the union of those that name
    /// the caller).
    pub by_acl: u32,
    /// The owner's `manage`.
    pub by_owner: u32,
}

impl Rights {
    pub fn all(&self) -> u32 {
        if self.admin {
            ACL_ALL
        } else {
            self.by_mode | self.by_acl | self.by_owner
        }
    }
}

pub fn rights(who: &Who, o: &Subject, list: &[AclEntry]) -> Rights {
    let (class, bits) = if who.uid == o.uid {
        (Class::Owner, (o.mode >> 6) & 7)
    } else if who.gid == o.gid {
        (Class::Group, (o.mode >> 3) & 7)
    } else {
        (Class::Other, o.mode & 7)
    };
    let by_mode = (if bits & 4 != 0 { ACL_READ } else { 0 })
        | (if bits & 2 != 0 { ACL_WRITE } else { 0 })
        | (if bits & 1 != 0 { ACL_RUN } else { 0 });
    let by_acl = list
        .iter()
        .filter(|e| match e.kind {
            ACL_USER => e.id == who.uid,
            ACL_GROUP => e.id == who.gid,
            _ => false,
        })
        .fold(0, |a, e| a | e.rights);
    Rights {
        admin: who.admin,
        class,
        by_mode,
        by_acl,
        by_owner: if who.uid == o.uid { ACL_MANAGE } else { 0 },
    }
}

/// May the caller do `access` (`O_*` bits)?
pub fn allows(who: &Who, o: &Subject, list: &[AclEntry], access: u64) -> bool {
    let need = wanted(access);
    rights(who, o, list).all() & need == need
}

fn names(r: u32, out: &mut impl Write) {
    let mut first = true;
    for (bit, n) in [
        (ACL_READ, "read"),
        (ACL_WRITE, "write"),
        (ACL_RUN, "run"),
        (ACL_MANAGE, "manage"),
    ] {
        if r & bit != 0 {
            let _ = write!(out, "{}{n}", if first { "" } else { ", " });
            first = false;
        }
    }
    if first {
        let _ = write!(out, "nothing");
    }
}

struct Buf<'a> {
    b: &'a mut [u8],
    n: usize,
}

impl Write for Buf<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let room = self.b.len() - self.n;
        let k = s.len().min(room);
        self.b[self.n..self.n + k].copy_from_slice(&s.as_bytes()[..k]);
        self.n += k;
        Ok(())
    }
}

/// The decision and the rule behind it, in words, into `out` (cut to
/// fit); the length. "allowed" or "denied", the rights asked for, then
/// what each source gives.
pub fn explain(who: &Who, o: &Subject, list: &[AclEntry], access: u64, out: &mut [u8]) -> usize {
    let r = rights(who, o, list);
    let need = wanted(access);
    let ok = r.all() & need == need;
    let mut w = Buf { b: out, n: 0 };
    let _ = write!(w, "{}: ", if ok { "allowed" } else { "denied" });
    names(need, &mut w);
    let _ = write!(w, " for user {} (group {})", who.uid, who.gid);
    if r.admin {
        let _ = write!(w, "; the fs.admin privilege allows everything");
        return w.n;
    }
    let class = match r.class {
        Class::Owner => "owner",
        Class::Group => "group",
        Class::Other => "other",
    };
    let _ = write!(w, "; mode {:04o}: {class} class gives ", o.mode & 0o7777);
    names(r.by_mode, &mut w);
    if r.by_owner != 0 {
        let _ = write!(w, "; the owner may manage");
    }
    if r.by_acl != 0 {
        let _ = write!(w, "; the access list gives ");
        names(r.by_acl, &mut w);
    } else if list.is_empty() {
        let _ = write!(w, "; no access list");
    } else {
        let _ = write!(w, "; no entry of the access list names this user or group");
    }
    if !ok {
        let _ = write!(w, "; missing ");
        names(need & !r.all(), &mut w);
        let _ = write!(
            w,
            " -- a mode bit for the class, an access list entry for this user or group, or fs.admin"
        );
    }
    w.n
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: Subject = Subject {
        uid: 1000,
        gid: 100,
        mode: 0o640,
    };
    const ME: Who = Who {
        uid: 1000,
        gid: 100,
        admin: false,
    };
    const GROUP: Who = Who {
        uid: 1001,
        gid: 100,
        admin: false,
    };
    const OTHER: Who = Who {
        uid: 1002,
        gid: 200,
        admin: false,
    };

    #[test]
    fn mode_classes_without_a_list() {
        assert!(allows(&ME, &FILE, &[], O_READ | O_WRITE));
        assert!(allows(&GROUP, &FILE, &[], O_READ));
        assert!(!allows(&GROUP, &FILE, &[], O_WRITE));
        assert!(!allows(&OTHER, &FILE, &[], O_READ));
        // Managing is the owner's.
        assert!(allows(&ME, &FILE, &[], O_MANAGE));
        assert!(allows(&ME, &FILE, &[], O_WRITE_ATTR));
        assert!(!allows(&GROUP, &FILE, &[], O_WRITE_ATTR));
        // The owner class is the owner's, whatever the group says.
        let locked = Subject {
            mode: 0o070,
            ..FILE
        };
        assert!(!allows(&ME, &locked, &[], O_READ));
        assert!(allows(&GROUP, &locked, &[], O_READ | O_WRITE));
    }

    #[test]
    fn a_list_adds_never_takes_away() {
        let list = [
            AclEntry::user(1002, ACL_READ),
            AclEntry::group(200, ACL_WRITE),
            AclEntry::user(1001, ACL_MANAGE),
        ];
        // OTHER: named as a user (read) and by its group (write).
        assert!(allows(&OTHER, &FILE, &list, O_READ | O_WRITE));
        assert!(!allows(&OTHER, &FILE, &list, O_MANAGE));
        // GROUP's own user entry adds manage; what the mode gave stays.
        assert!(allows(&GROUP, &FILE, &list, O_READ | O_MANAGE));
        assert!(!allows(&GROUP, &FILE, &list, O_WRITE));
        // The owner is unchanged by a list that does not name it.
        assert!(allows(&ME, &FILE, &list, O_READ | O_WRITE | O_MANAGE));
        // An entry that gives nothing the caller lacks changes nothing.
        assert!(!allows(
            &OTHER,
            &FILE,
            &[AclEntry::user(5, ACL_ALL)],
            O_READ
        ));
    }

    #[test]
    fn the_administrator_may_all() {
        let admin = Who {
            admin: true,
            ..OTHER
        };
        let none = Subject { mode: 0, ..FILE };
        assert!(allows(&admin, &none, &[], O_READ | O_WRITE | O_MANAGE));
    }

    #[test]
    fn lists_that_can_be_stored() {
        assert!(valid(&[]));
        assert!(valid(&[
            AclEntry::user(1, ACL_READ),
            AclEntry::group(1, ACL_WRITE)
        ]));
        // Twice, nothing given, unknown rights or kind, too many.
        assert!(!valid(&[
            AclEntry::user(1, ACL_READ),
            AclEntry::user(1, ACL_WRITE)
        ]));
        assert!(!valid(&[AclEntry::user(1, 0)]));
        assert!(!valid(&[AclEntry::user(1, 1 << 9)]));
        assert!(!valid(&[AclEntry {
            kind: 9,
            ..AclEntry::user(1, ACL_READ)
        }]));
        let many: [AclEntry; ACL_MAX + 1] =
            core::array::from_fn(|i| AclEntry::user(i as u32, ACL_READ));
        assert!(!valid(&many));
        assert!(valid(&many[..ACL_MAX]));
    }

    #[test]
    fn entries_round_trip() {
        let e = AclEntry::group(0xDEAD_BEEF, ACL_READ | ACL_MANAGE);
        assert_eq!(AclEntry::from_bytes(&e.to_bytes()), e);
        let mut bytes = [0u8; ACL_ENTRY_SIZE * 2 + 5];
        bytes[..ACL_ENTRY_SIZE].copy_from_slice(&e.to_bytes());
        bytes[ACL_ENTRY_SIZE..2 * ACL_ENTRY_SIZE]
            .copy_from_slice(&AclEntry::user(7, ACL_RUN).to_bytes());
        let got: std::vec::Vec<AclEntry> = parse(&bytes).collect();
        assert_eq!(got, [e, AclEntry::user(7, ACL_RUN)]);
        assert_eq!(ACL_ENTRY_SIZE, 12);
    }

    #[test]
    fn the_explanation_is_the_rule() {
        let mut b = [0u8; 400];
        let text = |who: &Who, list: &[AclEntry], access, b: &mut [u8; 400]| {
            let n = explain(who, &FILE, list, access, b);
            std::string::String::from_utf8_lossy(&b[..n]).into_owned()
        };
        let t = text(&GROUP, &[], O_READ, &mut b);
        assert!(
            t.starts_with("allowed: read") && t.contains("group class gives read"),
            "{t}"
        );
        let t = text(&GROUP, &[], O_WRITE, &mut b);
        assert!(
            t.starts_with("denied: write")
                && t.contains("missing write")
                && t.contains("no access list"),
            "{t}"
        );
        let t = text(&OTHER, &[AclEntry::user(1002, ACL_WRITE)], O_WRITE, &mut b);
        assert!(
            t.starts_with("allowed: write") && t.contains("the access list gives write"),
            "{t}"
        );
        let t = text(&OTHER, &[AclEntry::user(9, ACL_WRITE)], O_READ, &mut b);
        assert!(
            t.contains("no entry of the access list names this user or group"),
            "{t}"
        );
        let t = text(&ME, &[], O_MANAGE, &mut b);
        assert!(
            t.starts_with("allowed: manage") && t.contains("the owner may manage"),
            "{t}"
        );
        let t = text(
            &Who {
                admin: true,
                ..OTHER
            },
            &[],
            O_WRITE,
            &mut b,
        );
        assert!(t.contains("fs.admin"), "{t}");
        // Cut to fit, not past the buffer.
        let mut small = [0u8; 20];
        assert!(explain(&GROUP, &FILE, &[], O_WRITE, &mut small) <= 20);
        // The explanation and the decision agree, always.
        for who in [ME, GROUP, OTHER] {
            for access in [O_READ, O_WRITE, O_MANAGE, O_READ | O_WRITE] {
                let n = explain(&who, &FILE, &[], access, &mut b);
                let said = std::string::String::from_utf8_lossy(&b[..n]).starts_with("allowed");
                assert_eq!(said, allows(&who, &FILE, &[], access));
            }
        }
    }
}
