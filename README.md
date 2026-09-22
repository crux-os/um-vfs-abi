# um-vfs-abi

Crux OS VFS IPC protocol -- shared between the VFS server (um-vfs) and
every client (shell, future package manager, ...). Extracted from
um-vfs into its own repository so consumers depend on the stable
protocol contract, never on VFS implementation details.
