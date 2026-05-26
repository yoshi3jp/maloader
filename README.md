# maloader

maloader is an experimental Mach-O loader for Linux.

Its goal is to load and execute Mach-O binaries by implementing the loader-side
parts normally handled by dyld: segment mapping, rebasing, binding, chained fixups,
entry-point discovery, and process handoff.

maloader is not a full Darwin compatibility layer. It does not aim to implement
Mach IPC, XPC, CoreFoundation, launchd, kqueue, Darwin syscalls, Objective-C
runtime compatibility, sandboxing, code signing, or a complete libSystem.

Small Darwin/glibc shims may exist in-tree for testing, but they are treated as
proof-of-concept resolver backends and are expected to move into a separate
project.
