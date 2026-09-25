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

// ── status codes (negative on error, POSIX errno) ───────────────────────

// ── open modes (bitfield) ───────────────────────────────────────────────
pub const MODE_READ:     u64 = 1 << 0;
pub const MODE_WRITE:    u64 = 1 << 1;
pub const MODE_TRUNCATE: u64 = 1 << 2;
pub const MODE_CREATE:   u64 = 1 << 3;
pub const MODE_DIR:      u64 = 1 << 4;     // open() asserts entry is a dir

// ── inline-payload helpers ──────────────────────────────────────────────
//
// `payload[2..6]` carries 32 bytes of either a path or data.  Both ends
// agree on this packing:

pub const INLINE_BYTES: usize = 32;

/// Pack a path/data slice into payload[2..6].  Returns the slice
/// actually packed (truncated to INLINE_BYTES) so callers can detect
/// over-long paths and surface E_NAMETOOLONG locally.
#[inline]
pub fn pack_inline(payload: &mut [u64; 6], bytes: &[u8]) -> usize {
    let n = core::cmp::min(bytes.len(), INLINE_BYTES);
    let mut buf = [0u8; INLINE_BYTES];
    buf[..n].copy_from_slice(&bytes[..n]);
    payload[2] = u64::from_le_bytes(buf[ 0.. 8].try_into().unwrap());
    payload[3] = u64::from_le_bytes(buf[ 8..16].try_into().unwrap());
    payload[4] = u64::from_le_bytes(buf[16..24].try_into().unwrap());
    payload[5] = u64::from_le_bytes(buf[24..32].try_into().unwrap());
    n
}

/// Unpack payload[2..6] into a 32-byte buffer.  Callers detect the
/// effective end via the first NUL byte (for paths) or use an
/// explicit length carried elsewhere (for inline reads).
#[inline]
pub fn unpack_inline(payload: &[u64; 6]) -> [u8; INLINE_BYTES] {
    let mut buf = [0u8; INLINE_BYTES];
    buf[ 0.. 8].copy_from_slice(&payload[2].to_le_bytes());
    buf[ 8..16].copy_from_slice(&payload[3].to_le_bytes());
    buf[16..24].copy_from_slice(&payload[4].to_le_bytes());
    buf[24..32].copy_from_slice(&payload[5].to_le_bytes());
    buf
}

/// Return the index of the first NUL byte in `buf`, or `buf.len()` if
/// none exists.  Used to compute path length from unpacked inline.
#[inline]
pub fn cstr_len(buf: &[u8]) -> usize {
    let mut i = 0;
    while i < buf.len() && buf[i] != 0 { i += 1; }
    i
}

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
/// reply: [status, VERSION, window bytes]
pub const HELLO: u32 = 0x200;
/// OPEN(dir, path_len, flags, mode): path at window[0..path_len].
/// reply: [status, handle]; Stat of the opened object at window[0].
pub const OPEN: u32 = 0x201;
/// CLOSE(h). reply: [status]
pub const CLOSE: u32 = 0x202;
/// READ(h, offset, len): len <= window. reply: [status, n]; data at window[0..n].
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
    pub _pad: u8,
    pub name_len: u16,
    pub rec_len: u32,
}
pub const DIRENT_HEADER: usize = core::mem::size_of::<Dirent>();

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

/// Record length for a header of `header` bytes plus `n` bytes, 8-aligned.
pub const fn rec_len(header: usize, n: usize) -> usize {
    (header + n + 7) & !7
}
