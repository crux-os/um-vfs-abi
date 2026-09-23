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

/// SHM_ECHO -- proof-of-concept for the SYS_SHM_CREATE/SYS_SHM_MAP
/// zero-copy shared-memory primitive: the caller creates a shared
/// region, writes bytes into it, and sends um-vfs the region id +
/// byte count -- NOT the bytes themselves, unlike every other op
/// here (which embed up to INLINE_BYTES per message). um-vfs maps
/// the SAME physical pages and reads directly from them.
///   request: payload[0]=shm_id, payload[1]=len
///   reply:   payload[0]=status, payload[1]=bytes echoed back
///            (um-vfs writes its own reply text into the FIRST few
///            bytes of the same shared region, overwriting the
///            request -- the caller re-reads through its own mapping)
pub const OP_SHM_ECHO:  u32 = 0x1a;

// ── kinds ───────────────────────────────────────────────────────────────
pub const KIND_NONE:    u64 = 0;     // also used as "absent / EOF"
pub const KIND_FILE:    u64 = 1;
pub const KIND_DIR:     u64 = 2;
pub const KIND_SYMLINK: u64 = 3;

// ── status codes (negative on error, POSIX errno) ───────────────────────
pub const E_OK:          i64 = 0;
pub const E_NOTFOUND:    i64 = -2;
pub const E_IO:          i64 = -5;
pub const E_BADF:        i64 = -9;
pub const E_EXISTS:      i64 = -17;
pub const E_NOTDIR:      i64 = -20;
pub const E_ISDIR:       i64 = -21;
pub const E_INVAL:       i64 = -22;
pub const E_NOSPC:       i64 = -28;
pub const E_NAMETOOLONG: i64 = -36;
pub const E_NOSYS:       i64 = -38;

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
