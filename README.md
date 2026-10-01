# um-vfs-abi

Crux OS VFS IPC protocol -- shared between the VFS server (um-vfs) and
every client (shell, future package manager, ...). Extracted from
um-vfs into its own repository so consumers depend on the stable
protocol contract, never on VFS implementation details.

The protocol runs over an IPC v2 session with a shared-memory window
(the client is `runtime::fs` in rustspace). `OPEN` states the access it
wants (`O_READ`, `O_WRITE`, `O_WRITE_ATTR`, `O_MANAGE`); rights are
checked once at open, carried by the file handle and narrowed when
permissions change. `FORK` gives a forked child a session of its own:
copies of the open files under the same handles (offsets part from
there), its channel moved back in the reply. Details: crux-os `docs/architecture/vfs.md`.
