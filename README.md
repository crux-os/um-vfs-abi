# um-vfs-abi

Crux OS VFS IPC protocol -- shared between the VFS server (um-vfs) and
every client (shell, future package manager, ...). Extracted from
um-vfs into its own repository so consumers depend on the stable
protocol contract, never on VFS implementation details.

The protocol runs over an IPC v2 session with a shared-memory window
(the client is `runtime::fs` in rustspace). `OPEN` states the access it
wants (`O_READ`, `O_WRITE`, `O_WRITE_ATTR`, `O_MANAGE`); rights are
checked once at open, carried by the file handle and narrowed when
permissions change. Details: crux-os `docs/architecture/vfs.md`.
