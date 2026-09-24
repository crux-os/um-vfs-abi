//! um-vfs IPC protocol -- shared between the VFS server and every
//! client (shell, fileutils, init, future user programs).
//!
//! Single-message protocol: every op fits in one Message (4-byte
//! opcode + six u64 of payload = 48 bytes).  Paths and inline file
//! data live in `payload[2..6]` (32 bytes max in v1; longer paths and
//! larger reads/writes will be chunked once we need them).
//!
//! Reply layout: `opcode | OP_REPLY_BIT`, `payload[0]` = status (0 OK,
//! negative = errno-style), remaining slots op-specific.

#![cfg_attr(not(test), no_std)]
#![allow(missing_docs)]

pub const VFS_REQ_CAP:   u64 = 0x100;
pub const VFS_REPLY_CAP: u64 = 0x101;

pub const OP_REPLY_BIT: u32 = 0x80;

// ── operations ──────────────────────────────────────────────────────────
//
// Path / data inline area: payload[2..6] (4 * 8 = 32 bytes).  When a
// path is shorter, the trailing bytes must be zero so the server can
// detect the end via the first NUL.

/// STAT a path.
///   request: payload[2..6] = path
///   reply:   payload[0]=status, [1]=kind, [2]=size_bytes, [3]=mtime_ms
pub const OP_STAT:      u32 = 0x10;

/// READDIR -- ask for one entry at a given byte index inside the dir.
///   request: payload[0]=index, payload[2..6]=dir_path
///   reply:   payload[0]=status (E_NOTFOUND if index past end),
///            payload[1]=kind of entry, payload[2..6]=entry_name (NUL-padded)
pub const OP_READDIR:   u32 = 0x11;

/// OPEN.  Handle is small int unique to (server, client).
///   request: payload[0]=mode (MODE_*), payload[2..6]=path
///   reply:   payload[0]=status, payload[1]=handle
pub const OP_OPEN:      u32 = 0x12;

/// READ up to 32 bytes from a handle.
///   request: payload[0]=handle, payload[1]=offset
///   reply:   payload[0]=status, payload[1]=bytes_returned,
///            payload[2..6]=data (NUL-padded)
pub const OP_READ:      u32 = 0x13;

/// WRITE up to 32 bytes to a handle.
///   request: payload[0]=handle, payload[1]=offset, payload[2..6]=data,
///            payload[0]'s upper 32 bits = data_len.
///   We pack (handle | (len << 32)) into payload[0] since both are
///   small ints.
///   reply:   payload[0]=status, payload[1]=bytes_written
pub const OP_WRITE:     u32 = 0x14;

/// CLOSE a handle.
///   request: payload[0]=handle.
///   reply:   payload[0]=status.
pub const OP_CLOSE:     u32 = 0x15;

/// MKDIR.
///   request: payload[2..6]=path.
///   reply:   payload[0]=status.
pub const OP_MKDIR:     u32 = 0x16;

/// UNLINK (file or empty dir).
///   request: payload[2..6]=path.
///   reply:   payload[0]=status.
pub const OP_UNLINK:    u32 = 0x17;

/// TRUNCATE / set file length to `new_size`.
///   request: payload[0]=handle, payload[1]=new_size.
///   reply:   payload[0]=status.
pub const OP_TRUNCATE:  u32 = 0x18;

/// GC -- run CruxFS's mark-and-sweep metadata reclaim on whatever
/// disk um-vfs already has mounted. Routed through the live mount
/// deliberately: a second process opening the same disk independently
/// (as a standalone "run cfs --gc" would) races um-vfs's own writer,
/// two CoW commits to one superblock with the last write winning.
/// This is the same reason a real fs's maintenance ioctls (btrfs
/// balance/scrub, etc) go through the mounted instance instead of a
/// second concurrent mount.
///   request: (no payload)
///   reply:   payload[0]=status (E_NOSYS if no CruxFS mounted),
///            payload[1]=blocks_reclaimed
pub const OP_GC:        u32 = 0x19;

/// SHM_ECHO -- smoke test for shared memory. Sent WITH a region handle
/// attached (SYS_IPC_SEND_HANDLE, slot 0). um-vfs maps the region, logs
/// the first `len` bytes, writes its reply text over the start of the
/// region, then unmaps and closes its handle.
///   request: payload[0]=handle (attached), payload[1]=len
///   reply:   payload[0]=status, payload[1]=reply length
pub const OP_SHM_ECHO:  u32 = 0x1a;

/// READ_SHM -- bulk read into an attached region (see OP_SHM_ATTACH):
/// um-vfs reads file data straight into the region, no per-32-byte IPC.
///   request: payload[0]=handle, payload[1]=file_offset,
///            payload[2]=region token, payload[3]=region_offset, payload[4]=len
///   reply:   payload[0]=status, payload[1]=bytes_read (0 = EOF; fewer
///            than `len` only at EOF)
/// len <= BULK_MAX_BYTES and region_offset+len <= the region's size,
/// else E_INVAL.
pub const OP_READ_SHM:  u32 = 0x1b;

/// WRITE_SHM -- bulk write from an attached region. Same layout as
/// OP_READ_SHM; reply payload[1] = bytes_written. Writes to a CruxFS
/// handle must stay sequential, exactly like OP_WRITE.
pub const OP_WRITE_SHM: u32 = 0x1c;

/// SHM_ATTACH -- hand um-vfs a shared region for bulk transfers. Sent
/// with the region handle attached (SYS_IPC_SEND_HANDLE, slot 0). um-vfs
/// maps it once, checks its real size (SYS_SHM_SIZE) and returns a token
/// naming it in later *_SHM requests.
///   request: payload[0]=handle (attached)
///   reply:   payload[0]=status (E_INVAL if smaller than
///            BULK_MIN_REGION_BYTES, E_NOSPC if too many attached),
///            payload[1]=token, payload[2]=region size in bytes
pub const OP_SHM_ATTACH: u32 = 0x1d;

/// SHM_DETACH -- um-vfs unmaps the region and drops its handle.
///   request: payload[0]=token
///   reply:   payload[0]=status
pub const OP_SHM_DETACH: u32 = 0x1e;

/// Smallest region OP_SHM_ATTACH accepts.
pub const BULK_MIN_REGION_BYTES: usize = 4096;
/// Largest single *_SHM transfer.
pub const BULK_MAX_BYTES: usize = 1024 * 1024;
/// Region size clients should create for bulk transfers (room for two
/// maximal transfers, so a client can double-buffer).
pub const BULK_REGION_BYTES: usize = 2 * BULK_MAX_BYTES;

// ── kinds ───────────────────────────────────────────────────────────────
pub const KIND_NONE:    u64 = 0;     // also used as "absent / EOF"
pub const KIND_FILE:    u64 = 1;
pub const KIND_DIR:     u64 = 2;
pub const KIND_SYMLINK: u64 = 3;

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

// ════════════════════════════════════════════════════════════════════════
// Protocol v2 (docs/architecture/vfs.md in crux-os)
// ════════════════════════════════════════════════════════════════════════

/// VFS protocol v2: sessions over IPC v2 channels with a shared-memory
/// window for paths and bulk data.
///
/// A client connects to the service [`v2::SERVICE`], then sends
/// [`v2::HELLO`] with a shared-memory region (the *window*) moved in
/// payload slot 0. Requests carry integer arguments in the message
/// payload; paths and data travel in the window: a request's path starts
/// at window offset 0 (a second path, for rename/link/symlink, follows the
/// first), write data at offset 0; replies put data, `Stat`, directory
/// records at offset 0. One request in flight per session.
///
/// Reply: `payload[0]` = status (0 or a negative `facility:code`), then
/// operation-specific results.
pub mod v2 {
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
    /// SETATTR(h, mask, mode, uid<<32|gid, atime_ns, mtime_ns). reply: [status]
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

    // ── flags ───────────────────────────────────────────────────────────
    pub const O_READ: u64 = 1 << 0;
    pub const O_WRITE: u64 = 1 << 1;
    pub const O_CREATE: u64 = 1 << 2;
    pub const O_EXCL: u64 = 1 << 3;
    pub const O_TRUNC: u64 = 1 << 4;
    pub const O_APPEND: u64 = 1 << 5;
    pub const O_DIRECTORY: u64 = 1 << 6;
    pub const O_NOFOLLOW: u64 = 1 << 7;

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
        pub _pad: [u8; 7],
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
}
