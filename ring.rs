//! The request ring (docs/architecture/vfs-ring.md): requests of any
//! protocol operation, in shared memory, submitted in a batch and chained
//! (`SQE_LINK`), completions in a second array. The records and the
//! header are those of the `IoAPI` ring (netapi-design.md, section 6), so
//! the file API and the network API share one ring.
//!
//! The region is the program's: header page, the submission queue (SQ),
//! the completion queue (CQ), then a data area that requests point into
//! (paths, data, `Stat`s: what a request puts in the session's window,
//! it puts in its own part of the data area).

/// "CRXFSRNG": the first u64 of a ring's header.
pub const MAGIC: u64 = 0x474E_5253_4658_5243;
pub const VERSION: u32 = 1;
/// The header is one page.
pub const HEADER_SIZE: usize = 4096;

// Offsets in the header page. The server writes the fixed part at
// RING_CREATE; the counters are the two sides' (one writer each, each on
// its own cache line).
pub const H_MAGIC: usize = 0;
pub const H_VERSION: usize = 8;
pub const H_HEADER_SIZE: usize = 12;
/// Features the server accepted (u64).
pub const H_FEATURES: usize = 16;
pub const H_SQ_ENTRIES: usize = 24;
pub const H_CQ_ENTRIES: usize = 28;
/// Byte offsets (u64) in the region of the SQ, the CQ and the data area.
pub const H_SQ_OFF: usize = 32;
pub const H_CQ_OFF: usize = 40;
pub const H_DATA_OFF: usize = 48;
/// u64, only grows: requests the server took (it writes).
pub const H_SQ_HEAD: usize = 128;
/// u64, only grows: requests submitted (the program writes).
pub const H_SQ_TAIL: usize = 192;
/// u64, only grows: completions the program took (it writes).
pub const H_CQ_HEAD: usize = 256;
/// u64, only grows: completions posted (the server writes).
pub const H_CQ_TAIL: usize = 320;
/// u32: bits of who sleeps (`WAIT_*`), for futex waiters.
pub const H_WAIT: usize = 384;

/// A program that waits for completions reads the low 32 bits of
/// [`H_CQ_TAIL`], then sets `WAIT_PROGRAM` in the word at [`H_WAIT`], looks at
/// the CQ again, and sleeps on that word of the tail with the value it read
/// (futex on shared memory); the server, after it posts completions,
/// clears the bit and wakes the sleepers if it was set. The order matters:
/// with the bit set before the tail is read, a `notify` between the two
/// clears the bit while the value read already holds its completion, and
/// the next completion wakes nobody.
pub const WAIT_SERVER: u32 = 1;
pub const WAIT_PROGRAM: u32 = 2;

/// Features (none yet): `RING_CREATE` answers with the ones it accepted.
pub const FEATURES: u64 = 0;

/// Most entries of the SQ or the CQ (a power of two).
pub const ENTRIES_MAX: u32 = 4096;

/// A request. Fields as in netapi-design.md, section 6; what a VFS request
/// puts in them is [`Sqe::payload`].
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Sqe {
    /// A protocol operation (um_vfs_abi `OPEN`, `READ`...), run as the
    /// session would run it (an unknown one completes with `ENOSYS`, as
    /// there). One that passes a handle in its reply (`HELLO`, `FORK`,
    /// `VIEW`) or is the ring's own completes with `EINVAL`.
    pub opcode: u16,
    /// `SQE_*`.
    pub flags: u16,
    /// What the operation's first argument is (a file's handle, the base
    /// directory): [`H_ROOT`] for the root, [`H_PREV`] for the file the
    /// chain's last `OPEN` with [`SQE_FIXED`] opened; else a handle of the
    /// session.
    pub handle: u32,
    /// Comes back in the completion.
    pub user_data: u64,
    /// Where the request's window starts in the region (inside the data
    /// area), and how long it is: paths and data go there as they go in
    /// the session's window.
    pub addr: u64,
    pub len: u32,
    /// The operation's fifth argument (`OPEN`: bytes to read ahead).
    pub buf: u32,
    /// With [`SQE_DEADLINE`]: when the request must have started by.
    pub deadline: u64,
    /// The operation's second to fourth arguments.
    pub aux: [u64; 3],
}

/// The next request runs only if this one succeeded; else it completes
/// with `ECANCELED`, and so does each after it up to the first without
/// `SQE_LINK` (the chain). Chains are what ends a round trip per file.
pub const SQE_LINK: u16 = 1 << 0;
/// Not before every request before it has completed. (Requests are run in
/// order, so this holds anyway; asked for by the format, kept for rings
/// that run requests side by side.)
pub const SQE_DRAIN: u16 = 1 << 1;
/// On `OPEN`: the file is the chain's, not the program's: later requests of
/// the chain name it as [`H_PREV`], and it is closed when the chain ends,
/// done or cut short. The completion's `res` is 0.
pub const SQE_FIXED: u16 = 1 << 2;

/// `Sqe::deadline` is an absolute time (nanoseconds of the monotonic
/// clock, `runtime::time::Instant`): a request the server has not started
/// by then completes with `ETIMEDOUT` (and cuts its chain short). A
/// request that runs is not interrupted.
pub const SQE_DEADLINE: u16 = 1 << 3;

/// [`Sqe::handle`]: the root directory (what the protocol's `ROOT` is).
pub const H_ROOT: u32 = u32::MAX;
/// [`Sqe::handle`]: the file the chain opened with [`SQE_FIXED`].
pub const H_PREV: u32 = u32::MAX - 1;

pub const SQE_SIZE: usize = 64;

/// The completion `res` of a request cut short by the failure of the one
/// before it in its chain: `-ECANCELED`, the generic facility's POSIX
/// number (the error registry does not list it yet).
pub const ECANCELED: i32 = -125;

/// A completion.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Cqe {
    pub user_data: u64,
    /// 0 or more: the operation's result (what the protocol puts in the
    /// reply's `payload[1]`: bytes read, a new handle...); negative: a
    /// status `-((facility << 16) | code)`, as on the wire.
    pub res: i32,
    /// `CQE_*` (none yet).
    pub flags: u32,
    /// The reply's `payload[3]`.
    pub buf: u32,
    pub _pad: u32,
    /// The reply's `payload[2]`.
    pub aux: u64,
}

pub const CQE_SIZE: usize = 32;

/// Whether `n` is a size of the SQ or the CQ.
pub fn valid_entries(n: u64) -> bool {
    n >= 1 && n <= ENTRIES_MAX as u64 && n.is_power_of_two()
}

/// Where the SQ, the CQ and the data area start in a region with `sq` and
/// `cq` entries (data from the page after the CQ).
pub fn layout(sq: u32, cq: u32) -> (usize, usize, usize) {
    let sq_off = HEADER_SIZE;
    let cq_off = sq_off + sq as usize * SQE_SIZE;
    let data_off = (cq_off + cq as usize * CQE_SIZE).next_multiple_of(4096);
    (sq_off, cq_off, data_off)
}

impl Sqe {
    /// The arguments of the protocol request this one stands for: `handle`
    /// (resolved by the caller), then `aux`, then `buf`.
    pub fn payload(&self, handle: u64) -> [u64; 6] {
        [
            handle,
            self.aux[0],
            self.aux[1],
            self.aux[2],
            self.buf as u64,
            0,
        ]
    }
}

/// Whether `op` may be a ring request: it must not need a handle in its
/// reply or belong to the ring or the session's start.
pub fn allowed(op: u32) -> bool {
    use crate::{FORK, HELLO, RING_CREATE, RING_DESTROY, RING_ENTER, VIEW};
    !matches!(
        op,
        HELLO | FORK | VIEW | RING_CREATE | RING_ENTER | RING_DESTROY
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_have_the_sizes_of_the_format() {
        assert_eq!(core::mem::size_of::<Sqe>(), SQE_SIZE);
        assert_eq!(core::mem::size_of::<Cqe>(), CQE_SIZE);
        assert_eq!(core::mem::align_of::<Sqe>(), 8);
    }

    #[test]
    fn layout_is_page_aligned_and_in_order() {
        let (sq, cq, data) = layout(64, 128);
        assert_eq!(sq, HEADER_SIZE);
        assert_eq!(cq, sq + 64 * SQE_SIZE);
        assert!(data >= cq + 128 * CQE_SIZE && data % 4096 == 0);
        assert!(data - (cq + 128 * CQE_SIZE) < 4096);
    }

    #[test]
    fn header_fields_do_not_overlap_and_counters_have_lines() {
        let counters = [H_SQ_HEAD, H_SQ_TAIL, H_CQ_HEAD, H_CQ_TAIL, H_WAIT];
        for (i, a) in counters.iter().enumerate() {
            assert!(a % 64 == 0);
            for b in &counters[i + 1..] {
                assert!(a.abs_diff(*b) >= 64);
            }
        }
        assert!(H_DATA_OFF + 8 <= H_SQ_HEAD && H_WAIT + 4 <= HEADER_SIZE);
    }

    #[test]
    fn entries_are_powers_of_two() {
        assert!(valid_entries(1) && valid_entries(4096));
        assert!(!valid_entries(0) && !valid_entries(3) && !valid_entries(8192));
    }

    #[test]
    fn ring_operations_are_not_ring_requests() {
        assert!(!allowed(crate::HELLO) && !allowed(crate::RING_ENTER));
        assert!(allowed(crate::OPEN) && allowed(crate::READ) && allowed(crate::STAT));
    }

    #[test]
    fn payload_is_the_protocols_arguments() {
        let s = Sqe {
            aux: [1, 2, 3],
            buf: 4,
            ..Default::default()
        };
        assert_eq!(s.payload(9), [9, 1, 2, 3, 4, 0]);
    }
}
