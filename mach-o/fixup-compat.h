#ifndef MAL_MACH_O_FIXUP_COMPAT_H
#define MAL_MACH_O_FIXUP_COMPAT_H

/*
 * Project-local compatibility constants for dyld chained fixups.
 *
 * Keep these separate from vendored Apple headers.  Some Apple headers define
 * these as enum constants, not preprocessor macros, so #ifdef cannot reliably
 * test for their presence.
 */

#define MAL_DYLD_CHAINED_PTR_START_NONE   0xFFFF
#define MAL_DYLD_CHAINED_PTR_START_MULTI  0x8000

enum {
    MAL_DYLD_CHAINED_IMPORT           = 1,
    MAL_DYLD_CHAINED_IMPORT_ADDEND    = 2,
    MAL_DYLD_CHAINED_IMPORT_ADDEND64  = 3,
};

enum {
    MAL_DYLD_CHAINED_PTR_ARM64E             = 1,
    MAL_DYLD_CHAINED_PTR_64                 = 2,
    MAL_DYLD_CHAINED_PTR_32                 = 3,
    MAL_DYLD_CHAINED_PTR_32_CACHE           = 4,
    MAL_DYLD_CHAINED_PTR_32_FIRMWARE        = 5,
    MAL_DYLD_CHAINED_PTR_64_OFFSET          = 6,
    MAL_DYLD_CHAINED_PTR_ARM64E_OFFSET      = 7,
    MAL_DYLD_CHAINED_PTR_ARM64E_KERNEL      = 7,
    MAL_DYLD_CHAINED_PTR_64_KERNEL_CACHE    = 8,
    MAL_DYLD_CHAINED_PTR_ARM64E_USERLAND    = 9,
    MAL_DYLD_CHAINED_PTR_ARM64E_FIRMWARE    = 10,
    MAL_DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE = 11,
    MAL_DYLD_CHAINED_PTR_ARM64E_USERLAND24  = 12,
};

#endif
