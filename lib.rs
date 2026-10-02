//! The VFS protocol -- shared between the VFS server (um-vfs) and every
//! client (runtime::fs, and through it every program).
//!
//! Sessions over IPC channels with a shared-memory window for paths and
//! bulk data. A client connects to the service [`SERVICE`], then sends
//! [`HELLO`] with a shared-memory region (the *window*) moved in payload
//! slot 0. Requests carry integer arguments in the message payload;
//! paths and data travel in the window: a request's path starts at
//! window offset 0 (a second path, for rename/link/symlink, follows the
//! first), write data at offset 0; replies put data, `Stat`, directory
//! records at offset 0. One request in flight per session. See
//! docs/architecture/vfs.md in crux-os.
//!
//! Reply: `payload[0]` = status (0 or a negative `facility:code`), then
//! operation-specific results.

#![cfg_attr(not(test), no_std)]
#![allow(missing_docs)]

// ── status codes ────────────────────────────────────────────────────────
//
// Reply status (payload[0]) is a system status from the error registry
// (zigbone_abi::errors): 0 = OK, else `facility:code`. Generic errors
// (ENOENT, EIO, ENOSPC, ...) are used wherever they fit; VFS-specific
// conditions use the `vfs` facility, and filesystem-format errors from
// CruxFS pass through with the `cfs` facility.
pub use zigbone_abi::errors::{Error, Status, cfs as cfs_errors, vfs as errors};

/// Service-directory name.
pub const SERVICE: &[u8] = b"vfs";
pub const VERSION: u64 = 2;

/// Longest path, in bytes (NUL not included).
pub const PATH_MAX: usize = 32768;
/// Longest name of one path component.
pub const NAME_MAX: usize = 255;
/// Window size clients create by default (paths + one 1 MiB transfer).
pub const WINDOW_DEFAULT: usize = 1 << 20;
/// Smallest window the server accepts (must hold a PATH_MAX path).
pub const WINDOW_MIN: usize = 64 * 1024;
/// Most symbolic links followed while resolving one path.
pub const SYMLINK_MAX: usize = 40;
/// Directory handle meaning "the root" for *at-style operations.
pub const ROOT: u64 = u64::MAX;

// ── operations ──────────────────────────────────────────────────────
/// HELLO: window handle moved in slot 0.
/// reply: [status, VERSION, window bytes, change page]: the change page
/// is a read-only shared-memory handle (MSG_FLAG_HANDLE), see [`CHANGES_SLOT`].
pub const HELLO: u32 = 0x200;
/// Reply slot of HELLO with the change page: one page, a u64 counter at
/// offset 0 that the server increments after every request that may
/// change what STAT, FSTAT, READLINK or READDIR report (anyone's), and
/// after mounts and unmounts. A client may keep a result while the
/// counter still reads what it read before sending that request: no
/// request needed to ask again.
pub const CHANGES_SLOT: usize = 3;
/// OPEN(dir, path_len, flags, mode, ahead): path at window[0..path_len].
/// reply: [status, handle, n, read]; Stat of the opened object at
/// window[0]. With `ahead` > 0 and a regular file opened for reading, the
/// server also reads its first bytes, up to `ahead`, into
/// window[OPEN_DATA_AT..][..n] and sets `read` to 1: n < ahead means that
/// is the whole file (at the time of the request, see [`CHANGES_SLOT`]).
pub const OPEN: u32 = 0x201;
/// Where OPEN puts the data read ahead.
pub const OPEN_DATA_AT: usize = 4096;
/// Opcode bits 16..32 of any request may carry `h + 1` for a handle to
/// close before the request is served (quietly: no status for it). A
/// client closes read-only handles this way, riding its next request.
pub const CLOSE_FIRST_SHIFT: u32 = 16;
/// Largest handle [`CLOSE_FIRST_SHIFT`] can carry.
pub const CLOSE_FIRST_MAX: u64 = 0xFFFE;
/// CLOSE(h). reply: [status]
pub const CLOSE: u32 = 0x202;
/// READ(h, offset, len): len <= window. reply: [status, n]; data at
/// window[0..n]. n < len only at the end of the file.
pub const READ: u32 = 0x203;
/// WRITE(h, offset, len, flags): data at window[0..len]; WRITE_APPEND
/// ignores offset. reply: [status, n, new offset]
pub const WRITE: u32 = 0x204;
/// STAT(dir, path_len, flags=AT_NOFOLLOW?). reply: [status]; Stat at window[0].
pub const STAT: u32 = 0x205;
/// FSTAT(h). reply: [status]; Stat at window[0].
pub const FSTAT: u32 = 0x206;
/// TRUNCATE(h, size). reply: [status]
pub const TRUNCATE: u32 = 0x207;
/// FSYNC(h, flags=FSYNC_DATA?). reply: [status]
pub const FSYNC: u32 = 0x208;
/// MKDIR(dir, path_len, mode). reply: [status]
pub const MKDIR: u32 = 0x209;
/// UNLINK(dir, path_len, flags=AT_REMOVEDIR?). reply: [status]
pub const UNLINK: u32 = 0x20A;
/// RENAME(olddir, old_len, newdir, new_len, flags): old path at
/// window[0..old_len], new path right after it. reply: [status]
pub const RENAME: u32 = 0x20B;
/// LINK(olddir, old_len, newdir, new_len, flags): layout as RENAME.
pub const LINK: u32 = 0x20C;
/// SYMLINK(dir, path_len, target_len): path, then target. reply: [status]
pub const SYMLINK: u32 = 0x20D;
/// READLINK(dir, path_len). reply: [status, n]; target at window[0..n].
pub const READLINK: u32 = 0x20E;
/// READDIR(h, cookie): a batch of `Dirent` records filling the window.
/// Cookie 0 = start. reply: [status, count, next cookie, eof]
pub const READDIR: u32 = 0x20F;
/// READDIR_PLUS(h, cookie): [`READDIR`] with each entry's attributes, as
/// STAT without following a final symbolic link would give them: a
/// record is the `Dirent` header, a [`Stat`], then the name, padded to
/// 8 (`rec_len`, `DIRENT_PLUS_HEADER` before the name). A record with
/// `DIRENT_NO_ATTRS` in its `flags` has no attributes (the entry could not
/// be looked at, or is another one by now): its `Stat` is empty but for
/// `ino` and `kind`, ask STAT. One request for what `ls -l`, `find` and a
/// build tool otherwise ask a request per entry. Same reply as READDIR. A
/// name that does not fit the window at all is an error (ENAMETOOLONG),
/// not an empty batch.
pub const READDIR_PLUS: u32 = 0x21E;
/// SETATTR(h, mask, flags<<32|mode, uid<<32|gid, atime_ns, mtime_ns).
/// reply: [status]
pub const SETATTR: u32 = 0x210;
/// STATFS(dir). reply: [status]; StatFs at window[0].
pub const STATFS: u32 = 0x211;
/// FALLOCATE(h, offset, len, flags). reply: [status]
pub const FALLOCATE: u32 = 0x212;
/// COPY_RANGE(src, src_off, dst, dst_off, len, flags): copy inside the
/// server; shares extents (reflink) where the filesystem can.
/// reply: [status, bytes copied]
pub const COPY_RANGE: u32 = 0x213;
/// XATTR_GET(dir, path_len, name_len, flags=AT_NOFOLLOW?): path, then
/// name. reply: [status, n]; value at window[0..n].
pub const XATTR_GET: u32 = 0x214;
/// XATTR_SET(dir, path_len, name_len, value_len, flags): path, name,
/// value. flags: XATTR_CREATE / XATTR_REPLACE. reply: [status]
pub const XATTR_SET: u32 = 0x215;
/// XATTR_LIST(dir, path_len). reply: [status, n]; names, each
/// followed by NUL, at window[0..n].
pub const XATTR_LIST: u32 = 0x216;
/// XATTR_REMOVE(dir, path_len, name_len). reply: [status]
pub const XATTR_REMOVE: u32 = 0x217;
/// SYNC(volume dir): everything written so far becomes durable.
/// reply: [status]
pub const SYNC: u32 = 0x218;
/// READ_FILE(dir, path_len): open for reading and read from the start,
/// the window's worth. reply: [status, n, h, size]; data at
/// window[0..n]. n < window: that is the whole file, nothing stays open.
/// Otherwise h is open for reading the rest (READ from n, then CLOSE)
/// and size is the file's size at open.
pub const READ_FILE: u32 = 0x219;
/// WRITE_FILE(dir, path_len, len, mode, flags): create the file (as OPEN
/// with [`O_CREATE`] | [`O_TRUNC`] | [`O_WRITE`]; `flags` may add
/// [`O_EXCL`]), write the `len` bytes at window[WRITE_FILE_DATA_AT..] as
/// its whole contents and close it: what `fs::write` is, in one request
/// instead of three. Path at window[0..path_len]; `len` at most the
/// window less [`WRITE_FILE_DATA_AT`] (a bigger one is written the usual
/// way). reply: [status, n]; n < len: the file system took no more.
pub const WRITE_FILE: u32 = 0x21D;
/// Where WRITE_FILE takes its data from (after the longest path).
pub const WRITE_FILE_DATA_AT: usize = PATH_MAX;
/// VIEW(h, reads, flags): a shared view of regular file `h` (opened
/// for reading), for a client that reads it at scattered places
/// (`reads`: how many so far; the server may want more before it copies
/// a big file). With [`VIEW_WRITE`] in `flags` (`h` opened for writing
/// too; `reads` does not matter) the view is writable: what the client
/// stores in it is the file's contents for every reader at once, and the
/// server writes it to the file system at [`VIEW_SYNC`], at fsync and
/// SYNC, and when it leaves the view behind. reply: [status, _, _,
/// view]: the view is a shared-memory handle in [`VIEW_SLOT`]
/// (read-only without [`VIEW_WRITE`]) laid out as
/// [`VIEW_SIZE_AT`], [`VIEW_DEAD_AT`] and data from [`VIEW_DATA_AT`].
/// The server keeps it the file's contents: writes and truncations
/// land in it before their reply. While the dead word reads 0, bytes
/// `[0, size)` of the data are the file; once it reads nonzero the view
/// is left behind (unmap it; READ, or a new VIEW, from then on).
/// EAGAIN: not yet worth it (ask again after more reads); EFBIG,
/// ENOMEM: not for this file now.
pub const VIEW: u32 = 0x21A;
/// Reply slot of VIEW with the view's handle.
pub const VIEW_SLOT: usize = 3;
/// u64 at this offset of a view: the file's size.
pub const VIEW_SIZE_AT: usize = 0;
/// u64 at this offset of a view: nonzero once the view is left behind.
pub const VIEW_DEAD_AT: usize = 8;
/// Where a view's data starts.
pub const VIEW_DATA_AT: usize = 4096;
/// VIEW flag: a writable view.
pub const VIEW_WRITE: u64 = 1;
/// VIEW_SYNC(h, offset, len): bytes [offset, offset+len) of `h`'s
/// writable view written to the file system and made durable (msync).
/// reply: [status]; ENOENT: `h` has no writable view (any more).
pub const VIEW_SYNC: u32 = 0x21C;
/// FORK(count): a new session for a forked child (or a program started
/// or exec'd with open files): the same open files under the same
/// handles (each its own copy: offsets part from here), the same
/// identity, no window yet (HELLO first). `count` 0: every open file
/// (the one request a session may make before its HELLO); otherwise only
/// the `count` handles listed as u64 at the start of the window.
/// reply: [status, -, -, -]; the new session's channel moved in
/// [`FORK_SLOT`]. The child takes that one; the parent closes its copy.
pub const FORK: u32 = 0x21B;
/// Reply slot of FORK with the new session's channel.
pub const FORK_SLOT: usize = 3;
/// TRASH(dir, path_len): move to the volume's trash. reply: [status, id]
pub const TRASH: u32 = 0x220;
/// TRASH_LIST(cookie, volume dir): `TrashEntry` records filling the
/// window. reply: [status, count, next cookie, eof]
pub const TRASH_LIST: u32 = 0x221;
/// TRASH_RESTORE(id, volume dir, dest dir, dest_len): dest_len 0 =
/// the original path. reply: [status]
pub const TRASH_RESTORE: u32 = 0x222;
/// TRASH_PURGE(id, volume dir). reply: [status]
pub const TRASH_PURGE: u32 = 0x223;
/// TRASH_EMPTY(volume dir). reply: [status, entries removed]
pub const TRASH_EMPTY: u32 = 0x224;

/// SNAPSHOT(volume dir, op, name_len): name at window. Snapshots are
/// read-only views listed in the volume's `/.snapshots` directory.
/// reply: [status, id]
pub const SNAPSHOT: u32 = 0x230;
/// QUOTA(volume dir, op, uid, limit_blocks, limit_inodes): QUOTA_GET or
/// QUOTA_SET (limits in blocks of StatFs::block_size; 0 = none).
/// reply: [status, used_blocks, limit_blocks, used_inodes, limit_inodes]
pub const QUOTA: u32 = 0x231;
/// SCRUB(volume dir, cursor, budget blocks): verify checksums from the
/// device; cursor 0 starts (with all metadata), continue with `next`.
/// reply: [status, next (0 = done), data blocks checked, bad nodes,
/// bad blocks]; bad block numbers (u64) at window, as many as fit.
pub const SCRUB: u32 = 0x232;
/// FSCK(volume dir, flags=FSCK_REPAIR?): check the volume (and repair
/// it). reply: [status, problems found (0 = clean), items dropped,
/// objects moved to /lost+found]; a message at window, NUL-terminated.
pub const FSCK: u32 = 0x233;

/// SUBVOLUME_CREATE(dir, path_len): a new, empty subvolume at the path (a
/// directory that is a tree of its own: snapshots can be taken of it).
/// reply: [status]
pub const SUBVOLUME_CREATE: u32 = 0x234;
/// SNAPSHOT_AT(src dir, src_len, dst dir, dst_len, flags=SNAPSHOT_READONLY?):
/// snapshot of the subvolume (or volume root, or snapshot) at the source
/// path, created at the destination path (layout as RENAME); writable
/// unless SNAPSHOT_READONLY. reply: [status]
pub const SNAPSHOT_AT: u32 = 0x235;
/// SUBVOLUME_DELETE(dir, path_len): delete the subvolume or snapshot at
/// the path with everything in it. reply: [status]
pub const SUBVOLUME_DELETE: u32 = 0x236;

// ── flags ───────────────────────────────────────────────────────────
// ── OPEN flags ──────────────────────────────────────────────────────
// Access: every OPEN says what the handle is for -- at least one of
// O_READ, O_WRITE, O_WRITE_ATTR (EINVAL otherwise, like an access mode
// in POSIX open or dwDesiredAccess in CreateFile) -- and a handle does
// only that (EBADF otherwise). Asking for write access to something on a
// read-only file system fails at OPEN with EROFS.

/// Read data; list a directory.
pub const O_READ: u64 = 1 << 0;
/// Write data, truncate.
pub const O_WRITE: u64 = 1 << 1;
pub const O_CREATE: u64 = 1 << 2;
pub const O_EXCL: u64 = 1 << 3;
pub const O_TRUNC: u64 = 1 << 4;
pub const O_APPEND: u64 = 1 << 5;
pub const O_DIRECTORY: u64 = 1 << 6;
pub const O_NOFOLLOW: u64 = 1 << 7;
/// Change attributes (SETATTR: mode, owner, times, flags), also of a
/// directory. The owner's right.
pub const O_WRITE_ATTR: u64 = 1 << 8;
/// Manage the volume the directory is on: snapshots, quotas, repair,
/// restoring and purging the trash. The owner's right.
pub const O_MANAGE: u64 = 1 << 9;
/// The access bits: an OPEN needs at least one. Permissions are checked
/// once, at OPEN (EACCES: no handle). When they change (or the volume
/// turns read-only), every open handle loses at once the rights they no
/// longer give: calls needing a lost right fail with EACCES; a handle
/// left with none can only be closed.
pub const O_ACCESS: u64 = O_READ | O_WRITE | O_WRITE_ATTR | O_MANAGE;

pub const AT_NOFOLLOW: u64 = 1 << 0;
pub const AT_REMOVEDIR: u64 = 1 << 1;

pub const RENAME_NOREPLACE: u64 = 1 << 0;
pub const RENAME_EXCHANGE: u64 = 1 << 1;

pub const WRITE_APPEND: u64 = 1 << 0;
pub const FSYNC_DATA: u64 = 1 << 0;
/// COPY_RANGE: fail with EOPNOTSUPP rather than copy the bytes.
pub const COPY_REFLINK_ONLY: u64 = 1 << 0;

pub const XATTR_CREATE: u64 = 1 << 0;
pub const XATTR_REPLACE: u64 = 1 << 1;
/// Longest attribute name and value.
pub const XATTR_NAME_MAX: usize = 255;
pub const XATTR_SIZE_MAX: usize = 65536;

pub const SNAPSHOT_CREATE: u64 = 1;
pub const SNAPSHOT_DELETE: u64 = 2;
pub const SNAPSHOT_READONLY: u64 = 1 << 0;
/// Name of the snapshot directory at a volume's root.
pub const SNAPSHOT_DIR: &[u8] = b".snapshots";

pub const QUOTA_GET: u64 = 1;
pub const QUOTA_SET: u64 = 2;

pub const FSCK_REPAIR: u64 = 1 << 0;

pub const SETATTR_MODE: u64 = 1 << 0;
pub const SETATTR_UID: u64 = 1 << 1;
pub const SETATTR_GID: u64 = 1 << 2;
pub const SETATTR_ATIME: u64 = 1 << 3;
pub const SETATTR_MTIME: u64 = 1 << 4;
/// `Stat::flags` (FLAG_*), in bits 32..40 of the mode word.
pub const SETATTR_FLAGS: u64 = 1 << 5;

// ── object flags (Stat::flags) ──────────────────────────────────────
/// Not listed by default (`ls` without -a, file dialogs); like a name
/// starting with '.', but set on the object (FAT/exFAT: the hidden
/// attribute).
pub const FLAG_HIDDEN: u8 = 1 << 0;

// ── object kinds ────────────────────────────────────────────────────
pub const KIND_FILE: u8 = 1;
pub const KIND_DIR: u8 = 2;
pub const KIND_SYMLINK: u8 = 3;
pub const KIND_FIFO: u8 = 4;
/// A device file of the VFS itself (devfs): what is read and written is
/// not stored, so no read-ahead at OPEN and no view are made of it.
pub const KIND_CHAR: u8 = 5;

/// Metadata of a file system object.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Stat {
    pub ino: u64,
    pub dev: u64,
    pub size: u64,
    /// Bytes of storage actually allocated (sparse files use less).
    pub allocated: u64,
    pub atime_ns: u64,
    pub mtime_ns: u64,
    pub ctime_ns: u64,
    pub btime_ns: u64,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub kind: u8,
    /// FLAG_*.
    pub flags: u8,
    pub _pad: [u8; 6],
}

/// Volume statistics.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct StatFs {
    pub block_size: u64,
    pub total_blocks: u64,
    pub free_blocks: u64,
    pub total_inodes: u64,
    pub free_inodes: u64,
    pub name_max: u64,
    /// FEATURE_* bits.
    pub features: u64,
    pub dev: u64,
}
/// `StatFs::dev` of a volume on a disk partition (every /volN):
/// `VOLUME_DEV | disk << 48 | start`, `disk` the block slot index
/// (BLK_DEVn), `start` the partition's first sector -- so a tool can tell
/// which partition a mount point is (the installer finds the volume it
/// just created). Other file systems (tmpfs, the boot archive) have small
/// numbers without this bit.
pub const VOLUME_DEV: u64 = 1 << 63;

pub const fn volume_dev(disk: u64, start: u64) -> u64 {
    VOLUME_DEV | (disk & 0x7FFF) << 48 | (start & 0xFFFF_FFFF_FFFF)
}

/// (disk, start) of a volume's `dev`, None for other file systems.
pub const fn volume_source(dev: u64) -> Option<(u64, u64)> {
    if dev & VOLUME_DEV == 0 {
        None
    } else {
        Some(((dev >> 48) & 0x7FFF, dev & 0xFFFF_FFFF_FFFF))
    }
}

pub const FEATURE_REFLINK: u64 = 1 << 0;
pub const FEATURE_TRASH: u64 = 1 << 1;
pub const FEATURE_HARDLINKS: u64 = 1 << 2;
pub const FEATURE_SYMLINKS: u64 = 1 << 3;
pub const FEATURE_SPARSE: u64 = 1 << 4;
pub const FEATURE_PERSISTENT: u64 = 1 << 5;
pub const FEATURE_READONLY: u64 = 1 << 6;
pub const FEATURE_XATTR: u64 = 1 << 7;
pub const FEATURE_SNAPSHOTS: u64 = 1 << 8;
pub const FEATURE_QUOTA: u64 = 1 << 9;
pub const FEATURE_SCRUB: u64 = 1 << 10;
pub const FEATURE_SUBVOLUMES: u64 = 1 << 11;

/// One directory entry in a READDIR batch: this header, then `name_len`
/// bytes of name, padded so the next record is 8-aligned (`rec_len`).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct Dirent {
    pub ino: u64,
    /// Cookie that resumes the listing after this entry.
    pub next: u64,
    pub kind: u8,
    /// DIRENT_*.
    pub flags: u8,
    pub name_len: u16,
    pub rec_len: u32,
}
/// `Dirent::flags`: a [`READDIR_PLUS`] record without attributes.
pub const DIRENT_NO_ATTRS: u8 = 1 << 0;
pub const DIRENT_HEADER: usize = core::mem::size_of::<Dirent>();
/// Where the name of a [`READDIR_PLUS`] record starts.
pub const DIRENT_PLUS_HEADER: usize = DIRENT_HEADER + core::mem::size_of::<Stat>();

/// One trashed item in a TRASH_LIST batch: header, then the original
/// path (`path_len` bytes), padded to 8 (`rec_len`).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct TrashEntry {
    pub id: u64,
    pub deleted_ns: u64,
    pub size: u64,
    pub next: u64,
    pub kind: u8,
    pub _pad: [u8; 3],
    pub path_len: u32,
    pub rec_len: u32,
    pub _pad2: u32,
}
pub const TRASH_HEADER: usize = core::mem::size_of::<TrashEntry>();

/// The attributes of a [`READDIR_PLUS`] record for the entry `ino` of kind
/// `kind`, from what a lookup by name gave (`None`: it failed): those, and
/// the record's flags; with no attributes, or those of another object (the
/// name leads elsewhere since the listing), an empty `Stat` and
/// `DIRENT_NO_ATTRS`.
pub fn plus_attrs(ino: u64, kind: u8, found: Option<Stat>) -> (Stat, u8) {
    match found {
        Some(st) if st.ino == ino => (st, 0),
        _ => (
            Stat {
                ino,
                kind,
                ..Stat::default()
            },
            DIRENT_NO_ATTRS,
        ),
    }
}

/// Record length for a header of `header` bytes plus `n` bytes, 8-aligned.
pub const fn rec_len(header: usize, n: usize) -> usize {
    (header + n + 7) & !7
}

/// Whether request `op` with arguments `p` only reads: the server may
/// answer it while a file system's commit writes (it takes no right to
/// change the file system). Opening without creating or truncating and
/// closing change only what the server keeps in memory. A writable view
/// ([`VIEW_WRITE`]) is a change: what clients store in it reaches the
/// file system through the server, and making one may copy the file up.
pub fn reads_only(op: u32, p: &[u64; 6]) -> bool {
    match op {
        READ | READ_FILE | STAT | FSTAT | READLINK | READDIR | READDIR_PLUS | STATFS
        | TRASH_LIST | XATTR_GET | XATTR_LIST | CLOSE => true,
        VIEW => p[2] & VIEW_WRITE == 0,
        OPEN => p[2] & (O_CREATE | O_TRUNC) == 0,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readdir_plus_attributes_or_the_flag() {
        let st = Stat {
            ino: 7,
            kind: KIND_FILE,
            nlink: 1,
            size: 10,
            ..Stat::default()
        };
        assert_eq!(plus_attrs(7, KIND_FILE, Some(st)), (st, 0));
        // Not found: no attributes, and not by `nlink` being 0.
        let (e, f) = plus_attrs(7, KIND_FILE, None);
        assert_eq!(
            (f, e.ino, e.kind, e.size),
            (DIRENT_NO_ATTRS, 7, KIND_FILE, 0)
        );
        // The name leads to another object now.
        let (e, f) = plus_attrs(8, KIND_FILE, Some(st));
        assert_eq!((f, e.ino, e.size), (DIRENT_NO_ATTRS, 8, 0));
        // A file with no links left on the volume is not "no attributes".
        let gone = Stat { nlink: 0, ..st };
        assert_eq!(plus_attrs(7, KIND_FILE, Some(gone)), (gone, 0));
        assert_eq!(DIRENT_HEADER, 24);
    }

    #[test]
    fn reads_and_changes() {
        let none = [0u64; 6];
        for op in [
            READ, READ_FILE, STAT, FSTAT, READDIR, STATFS, XATTR_GET, CLOSE,
        ] {
            assert!(reads_only(op, &none), "{op:#x}");
        }
        for op in [
            WRITE, WRITE_FILE, TRUNCATE, MKDIR, UNLINK, RENAME, SETATTR, FSYNC, VIEW_SYNC,
        ] {
            assert!(!reads_only(op, &none), "{op:#x}");
        }
    }

    #[test]
    fn open_and_view_depend_on_flags() {
        let with = |i: usize, v: u64| {
            let mut p = [0u64; 6];
            p[i] = v;
            p
        };
        assert!(reads_only(OPEN, &with(2, O_READ)));
        assert!(!reads_only(OPEN, &with(2, O_WRITE | O_CREATE)));
        assert!(!reads_only(OPEN, &with(2, O_READ | O_TRUNC)));
        // A read-only view reads; a writable one changes the file system.
        assert!(reads_only(VIEW, &with(2, 0)));
        assert!(!reads_only(VIEW, &with(2, VIEW_WRITE)));
    }
}
