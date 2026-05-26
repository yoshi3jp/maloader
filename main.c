#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include "mach-o/loader.h"
#include "mach-o/nlist.h"
#include "mach-o/fixup-chains.h"
#include "mach-o/fixup-compat.h"

#include "machctrl.h"
#include "bind.h"

#ifndef MAL_VERBOSE_FIXUPS
#define MAL_VERBOSE_FIXUPS 0
#endif

#ifndef MAL_VERBOSE_SYMTAB
#define MAL_VERBOSE_SYMTAB 0
#endif

void* openExec(char* filename)
{
    void* memblock;
    int fd;
    struct stat sb;
    
    // load file
    fd = open(filename, O_RDONLY);
    fstat(fd, &sb);
    printf("Size: %llu\n", (uint64_t)sb.st_size);
    
    memblock = mmap(NULL, sb.st_size, PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (memblock == MAP_FAILED)
    {
        printf("Failed to open\n");
        exit(-1);
    }
    return memblock;
}

int determineBit(void* mach_header)
{
    uint32_t magic =  *((uint32_t*)mach_header);
    switch (magic) {
        case MH_MAGIC:
            return 32;
            break;
        case MH_MAGIC_64:
            return 64;
            break;
        default:
            exit(-1);
            break;
    }
}

void print_segment_64(struct segment_command_64 lc_segment)
{
    printf("cmd:0x%x\ncmdsize:0x%x\nsegname:%s\nvmaddr:0x%llx\nvmsize:0x%llx\nfileoff:0x%llx\nfilesize:0x%llx\nmaxprot:%d\ninitprot:%d\nnsects:%d\nflags:0x%x\n",
           lc_segment.cmd,
           lc_segment.cmdsize,
           lc_segment.segname,
           lc_segment.vmaddr,
           lc_segment.vmsize,
           lc_segment.fileoff,
           lc_segment.filesize,
           lc_segment.maxprot,
           lc_segment.initprot,
           lc_segment.nsects,
           lc_segment.flags
           );
}
void print_segment(struct segment_command lc_segment)
{
    printf("cmd:0x%x\ncmdsize:0x%x\nsegname:%s\nvmaddr:0x%lx\nvmsize:0x%lx\nfileoff:0x%lx\nfilesize:0x%lx\nmaxprot:%d\ninitprot:%d\nnsects:%d\nflags:0x%x\n",
           lc_segment.cmd,
           lc_segment.cmdsize,
           lc_segment.segname,
           lc_segment.vmaddr,
           lc_segment.vmsize,
           lc_segment.fileoff,
           lc_segment.filesize,
           lc_segment.maxprot,
           lc_segment.initprot,
           lc_segment.nsects,
           lc_segment.flags
           );
}
#if defined(__x86_64__) || defined(__aarch64__)
uint64_t alignMemory(uint64_t pointer, uint64_t alignment) {
#else
uint32_t alignMemory(uint32_t pointer, uint32_t alignment) {
#endif
    alignment--;
    return (pointer + alignment) & ~alignment;
}

static int ensure_image_mapping_64(mach_context* context)
{
    if (context->img_addr != NULL) {
        return 0;
    }

    struct mach_header_64* header = (struct mach_header_64*)context->memblock;
    uint8_t* p = (uint8_t*)context->memblock + sizeof(struct mach_header_64);

    uint64_t min_vmaddr = UINT64_MAX;
    uint64_t max_vmaddr = 0;

    for (uint32_t i = 0; i < header->ncmds; i++) {
        struct segment_command_64* seg = (struct segment_command_64*)p;

        if (seg->cmd == LC_SEGMENT_64 &&
            strcmp(seg->segname, "__PAGEZERO") &&
            seg->vmsize != 0) {
            if (seg->vmaddr < min_vmaddr) {
                min_vmaddr = seg->vmaddr;
            }

            if (seg->vmaddr + seg->vmsize > max_vmaddr) {
                max_vmaddr = seg->vmaddr + seg->vmsize;
            }
        }

        p += seg->cmdsize;
    }

    if (min_vmaddr == UINT64_MAX || max_vmaddr <= min_vmaddr) {
        printf("no mappable 64-bit segments found\n");
        return -1;
    }

    uint64_t map_size = alignMemory(max_vmaddr - min_vmaddr, 0x1000);

    printf("Allocating whole image 0x%llx bytes at 0x%llx\n",
           map_size,
           min_vmaddr);

    void* mapped = mmap((void*)min_vmaddr,
                        map_size,
                        PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_ANON | MAP_PRIVATE,
                        -1,
                        0);

    if (mapped == MAP_FAILED) {
        printf("Failed mapping whole image: %s\n", strerror(errno));
        return -1;
    }

    context->img_addr = mapped;
    context->v_addr = (void*)min_vmaddr;

    return 0;
}

int load_segment(mach_context* context)
{
    struct segment_command lc_segment = *((struct segment_command *)context->ptr);
    print_segment(lc_segment);
    //__TEXT
    if (!strcmp(lc_segment.segname, SEG_TEXT)) {
        printf("++++++++++++++++++\n");
        uint64_t filesize = alignMemory(lc_segment.filesize + 0x3000, 0x1000);
        //uint64_t vmsize = alignMemory(lc_segment.filesize, 0x1000);
        printf("Allocating 0x%lxbytes at 0x%lx\n",filesize,lc_segment.vmaddr);
        void* vm_segment = mmap((void*)lc_segment.vmaddr, filesize, PROT_READ | PROT_WRITE | PROT_EXEC , MAP_ANON | MAP_SHARED, -1, 0);
        if (vm_segment == MAP_FAILED) {
            printf("Failed mapping %s\n",lc_segment.segname);
        }
        memcpy(vm_segment, context->memblock, 0x3000);
        printf("vmsegment = 0x%lx\n",vm_segment);
        //int (*fp)(int argc, char *argv[]) = vm_segment;
        //(*fp)(0,NULL);
        context->img_addr = vm_segment;
        context->v_addr = lc_segment.vmaddr;
    }

    if (context->n_segment_info < MACH_LOADER_MAX_SEGMENTS) {
        segment_info* seg = &context->segments[context->n_segment_info++];

        memcpy(seg->segname, lc_segment.segname, sizeof(seg->segname));
        seg->vmaddr = (void*)lc_segment.vmaddr;
        seg->vmsize = lc_segment.vmsize;

        if (!strcmp(lc_segment.segname, "__PAGEZERO")) {
            seg->mapped_addr = NULL;
        } else if (!strcmp(lc_segment.segname, SEG_TEXT)) {
            seg->mapped_addr = context->img_addr;
        } else if (context->img_addr && context->v_addr) {
            seg->mapped_addr =
                (void*)((uintptr_t)context->img_addr +
                        (lc_segment.vmaddr - (uintptr_t)context->v_addr));
        } else {
            seg->mapped_addr = NULL;
        }

        printf("recorded segment[%d] %s vmaddr=0x%llx mapped=%p\n",
               context->n_segment_info - 1,
               seg->segname,
               lc_segment.vmaddr,
               seg->mapped_addr);
    }
    return lc_segment.nsects;
}

int load_segment_64(mach_context* context)
{
    struct segment_command_64 lc_segment = *((struct segment_command_64 *)context->ptr);
    print_segment_64(lc_segment);
    ensure_image_mapping_64(context);
    //__TEXT and other areas for modern binary
    if (strcmp(lc_segment.segname, "__PAGEZERO") &&
        lc_segment.filesize != 0 &&
        context->img_addr != NULL &&
        context->v_addr != NULL) {

        uint64_t base_vmaddr = (uint64_t)(uintptr_t)context->v_addr;
        uint64_t delta = lc_segment.vmaddr - base_vmaddr;

        void* dest = (uint8_t*)context->img_addr + delta;
        void* src = (uint8_t*)context->memblock + lc_segment.fileoff;

        memcpy(dest, src, lc_segment.filesize);

        printf("copied segment %s fileoff=0x%llx filesize=0x%llx -> %p\n",
               lc_segment.segname,
               lc_segment.fileoff,
               lc_segment.filesize,
               dest);
    }

    if (context->n_segment_info < MACH_LOADER_MAX_SEGMENTS) {
        segment_info* seg = &context->segments[context->n_segment_info++];

        memcpy(seg->segname, lc_segment.segname, sizeof(seg->segname));
        seg->vmaddr = (void*)lc_segment.vmaddr;
        seg->vmsize = lc_segment.vmsize;

        if (!strcmp(lc_segment.segname, "__PAGEZERO")) {
            seg->mapped_addr = NULL;
        } else if (!strcmp(lc_segment.segname, SEG_TEXT)) {
            seg->mapped_addr = context->img_addr;
        } else if (context->img_addr && context->v_addr) {
            seg->mapped_addr =
                (void*)((uintptr_t)context->img_addr +
                        (lc_segment.vmaddr - (uintptr_t)context->v_addr));
        } else {
            seg->mapped_addr = NULL;
        }

        printf("recorded segment[%d] %s vmaddr=0x%llx mapped=%p\n",
               context->n_segment_info - 1,
               seg->segname,
               lc_segment.vmaddr,
               seg->mapped_addr);
    }

    return lc_segment.nsects;
}

int load_section_64(mach_context* context)
{
    struct section_64 lc_section = *((struct section_64 *)context->ptr);
    printf("--- SectionName:%s@addr=0x%llx,ptr=%lx\n",lc_section.sectname,lc_section.addr,context->ptr - context->memblock);

//uint64_t* f2 = context->img_addr + 0x1010;
//*f2 = printf;
    return 0;
    
}

int load_section(mach_context* context)
{
    struct section lc_section = *((struct section *)context->ptr);
    printf("--- SectionName:%s@addr=0x%lx,ptr=%lx\n",lc_section.sectname,lc_section.addr,context->ptr - context->memblock);

//uint64_t* f2 = context->img_addr + 0x2008;
//*f2 = printf;
    return 0;
    
}

int dylib_list_retriever(mach_context* context, char *dylib_name)
{
    if(!(context->d_list.n_dylib_info != 0))
    {
        printf("First pass of DYLIB\n");
        context->d_list.info = malloc(sizeof(dylib_info));
        context->d_list.info[context->d_list.n_dylib_info].dylib_name = dylib_name;
        context->d_list.n_dylib_info ++;
        
    }else
    {
        context->d_list.info = realloc(context->d_list.info, sizeof(dylib_info) * (context->d_list.n_dylib_info + 1));
        context->d_list.info[context->d_list.n_dylib_info].dylib_name = dylib_name;
        context->d_list.n_dylib_info ++;
    }
    
    return 0;
}

static const char* chained_import_format_name(uint32_t fmt)
{
    switch (fmt) {
        case MAL_DYLD_CHAINED_IMPORT:
            return "DYLD_CHAINED_IMPORT";
        case MAL_DYLD_CHAINED_IMPORT_ADDEND:
            return "DYLD_CHAINED_IMPORT_ADDEND";
        case MAL_DYLD_CHAINED_IMPORT_ADDEND64:
            return "DYLD_CHAINED_IMPORT_ADDEND64";
        default:
            return "unknown";
    }
}

static const char* chained_symbol_format_name(uint32_t fmt)
{
    switch (fmt) {
        case 0:
            return "uncompressed";
        case 1:
            return "zlib compressed";
        default:
            return "unknown";
    }
}

static const char* chained_pointer_format_name(uint16_t fmt)
{
    switch (fmt) {
        case MAL_DYLD_CHAINED_PTR_ARM64E:
            return "DYLD_CHAINED_PTR_ARM64E";
        case MAL_DYLD_CHAINED_PTR_64:
            return "DYLD_CHAINED_PTR_64";
        case MAL_DYLD_CHAINED_PTR_64_OFFSET:
            return "DYLD_CHAINED_PTR_64_OFFSET";
        case MAL_DYLD_CHAINED_PTR_64_KERNEL_CACHE:
            return "DYLD_CHAINED_PTR_64_KERNEL_CACHE";
        case MAL_DYLD_CHAINED_PTR_32:
            return "DYLD_CHAINED_PTR_32";
        case MAL_DYLD_CHAINED_PTR_32_CACHE:
            return "DYLD_CHAINED_PTR_32_CACHE";
        case MAL_DYLD_CHAINED_PTR_32_FIRMWARE:
            return "DYLD_CHAINED_PTR_32_FIRMWARE";
        case MAL_DYLD_CHAINED_PTR_ARM64E_USERLAND:
            return "DYLD_CHAINED_PTR_ARM64E_USERLAND";
        case MAL_DYLD_CHAINED_PTR_ARM64E_USERLAND24:
            return "DYLD_CHAINED_PTR_ARM64E_USERLAND24";
        default:
            return "unknown";
    }
}

static void dump_chained_64_offset_entries(
    mach_context* context,
    const uint8_t* fixups_base,
    const struct dyld_chained_fixups_header* hdr,
    uint32_t segment_index,
    const struct dyld_chained_starts_in_segment* seg); //prototype

static void dump_chained_fixups(mach_context* context,
                                uint32_t dataoff,
                                uint32_t datasize)
{
    const uint8_t* fixups_base = (const uint8_t*)context->memblock + dataoff;
    const uint8_t* fixups_end = fixups_base + datasize;
    
    context->chained_rebase_count = 0;
    context->chained_bind_count = 0;

    if (datasize < sizeof(struct dyld_chained_fixups_header)) {
        printf("chained fixups too small\n");
        return;
    }

    const struct dyld_chained_fixups_header* hdr =
        (const struct dyld_chained_fixups_header*)fixups_base;

    printf("chained fixups header:\n");
    printf("  fixups_version:  %u\n", hdr->fixups_version);
    printf("  starts_offset:   0x%x\n", hdr->starts_offset);
    printf("  imports_offset:  0x%x\n", hdr->imports_offset);
    printf("  symbols_offset:  0x%x\n", hdr->symbols_offset);
    printf("  imports_count:   %u\n", hdr->imports_count);
    printf("  imports_format:  %u (%s)\n",
           hdr->imports_format,
           chained_import_format_name(hdr->imports_format));
    printf("  symbols_format:  %u (%s)\n",
           hdr->symbols_format,
           chained_symbol_format_name(hdr->symbols_format));

    if (hdr->starts_offset >= datasize) {
        printf("bad chained starts_offset\n");
        return;
    }

    const struct dyld_chained_starts_in_image* starts =
        (const struct dyld_chained_starts_in_image*)(fixups_base + hdr->starts_offset);

    if ((const uint8_t*)starts + sizeof(uint32_t) > fixups_end) {
        printf("bad chained starts table\n");
        return;
    }

    printf("chained starts in image:\n");
    printf("  seg_count: %u\n", starts->seg_count);

    for (uint32_t i = 0; i < starts->seg_count; i++) {
        uint32_t seg_info_off = starts->seg_info_offset[i];

        if (seg_info_off == 0) {
            printf("  segment[%u]: no chains\n", i);
            continue;
        }

        const struct dyld_chained_starts_in_segment* seg =
            (const struct dyld_chained_starts_in_segment*)
            ((const uint8_t*)starts + seg_info_off);

        if ((const uint8_t*)seg + sizeof(*seg) > fixups_end) {
            printf("  segment[%u]: bad seg_info_off=0x%x\n", i, seg_info_off);
            continue;
        }

        printf("  segment[%u]:\n", i);
        printf("    size:              0x%x\n", seg->size);
        printf("    page_size:         0x%x\n", seg->page_size);
        printf("    pointer_format:    %u (%s)\n",
               seg->pointer_format,
               chained_pointer_format_name(seg->pointer_format));
        printf("    segment_offset:    0x%llx\n", seg->segment_offset);
        printf("    max_valid_pointer: 0x%x\n", seg->max_valid_pointer);
        printf("    page_count:        %u\n", seg->page_count);

        for (uint16_t page = 0; page < seg->page_count && page < 8; page++) {
            printf("      page_start[%u]: 0x%x\n",
                   page,
                   seg->page_start[page]);
        }
        
        if (seg->pointer_format == MAL_DYLD_CHAINED_PTR_64_OFFSET) {
            dump_chained_64_offset_entries(context,
                                           fixups_base,
                                           hdr,
                                           i,
                                           seg);
        }

        if (seg->page_count > 8) {
            printf("      ...\n");
        }
    }
        printf("chained fixup summary: rebases=%u binds=%u\n",
           context->chained_rebase_count,
           context->chained_bind_count);
}

static uint32_t chained64_bind_ordinal(uint64_t raw)
{
    return raw & 0xFFFFFF;
}

static int8_t chained64_bind_addend(uint64_t raw)
{
    return (int8_t)((raw >> 24) & 0xFF);
}

static uint64_t chained64_rebase_target(uint64_t raw)
{
    return raw & 0xFFFFFFFFF; /* 36 bits */
}

static uint16_t chained64_next(uint64_t raw)
{
    return (raw >> 51) & 0xFFF;
}

static int chained64_is_bind(uint64_t raw)
{
    return (raw >> 63) & 1;
}

static const char* chained_import_name(const uint8_t* fixups_base,
                                       const struct dyld_chained_fixups_header* hdr,
                                       uint32_t ordinal)
{
    if (ordinal >= hdr->imports_count) {
        return NULL;
    }

    const struct dyld_chained_import* imports =
        (const struct dyld_chained_import*)(fixups_base + hdr->imports_offset);

    const char* symbols = (const char*)(fixups_base + hdr->symbols_offset);

    return symbols + imports[ordinal].name_offset;
}

static void apply_chained_64_offset_rebase(mach_context* context,
                                           uint8_t* loc,
                                           uint64_t raw)
{
    uint64_t target = chained64_rebase_target(raw);
    uint64_t final = (uint64_t)(uintptr_t)context->img_addr + target;
    
    #if MAL_VERBOSE_FIXUPS
    printf("      APPLY rebase loc=%p target=0x%llx final=0x%llx\n",
           loc,
           target,
           final);
    #endif

    *(uint64_t*)loc = final;
}

static void dump_chained_64_offset_entries(mach_context* context,
                                           const uint8_t* fixups_base,
                                           const struct dyld_chained_fixups_header* hdr,
                                           uint32_t segment_index,
                                           const struct dyld_chained_starts_in_segment* seg)
{
    if (segment_index >= context->n_segment_info) {
        printf("  segment[%u]: no matching loaded segment\n", segment_index);
        return;
    }

    segment_info* loaded_seg = &context->segments[segment_index];

    if (loaded_seg->mapped_addr == NULL) {
        printf("  segment[%u]: mapped_addr is NULL\n", segment_index);
        return;
    }

    printf("  segment[%u] chain entries:\n", segment_index);

    for (uint16_t page = 0; page < seg->page_count; page++) {
        uint16_t page_start = seg->page_start[page];

        if (page_start == MAL_DYLD_CHAINED_PTR_START_NONE) {
            continue;
        }

        if (page_start & MAL_DYLD_CHAINED_PTR_START_MULTI) {
            printf("    page[%u]: multi-start not implemented yet: 0x%x\n",
                   page,
                   page_start);
            continue;
        }

        uint64_t chain_offset =
            seg->segment_offset +
            ((uint64_t)page * seg->page_size) +
            page_start;

        uint8_t* loc = (uint8_t*)context->img_addr + chain_offset;

        printf("    page[%u] start=0x%x chain_offset=0x%llx loc=%p\n",
               page,
               page_start,
               chain_offset,
               loc);

        for (unsigned chain_count = 0; chain_count < 512; chain_count++) {
            uint64_t raw = *(uint64_t*)loc;
            uint16_t next = chained64_next(raw);

            if (chained64_is_bind(raw)) {
                uint32_t ordinal = chained64_bind_ordinal(raw);
                int8_t addend = chained64_bind_addend(raw);
                const char* name = chained_import_name(fixups_base, hdr, ordinal);

                printf("      bind   loc=%p raw=0x%016llx ordinal=%u addend=%d symbol=%s next=%u\n",
                       loc,
                       raw,
                       ordinal,
                       addend,
                       name ? name : "(bad ordinal)",
                       next);
                
                if (name) {
                    apply_chained_bind(context, loc, name, addend);
                } else {
                context->chained_bind_count++;
                context->chained_unresolved_bind_count++;
                }
            } else {
                uint64_t target = chained64_rebase_target(raw);
                void* final = (uint8_t*)context->img_addr + target;

                #if MAL_VERBOSE_FIXUPS
                printf("      rebase loc=%p raw=0x%016llx target=0x%llx final=%p next=%u\n",
                       loc,
                       raw,
                       target,
                       final,
                       next);         
                #endif

                apply_chained_64_offset_rebase(context, loc, raw);
                context->chained_rebase_count++;
            }

            if (next == 0) {
                break;
            }

            loc += next * 4;
        }
    }
}

int loader_64(mach_context* context)
{
    context->ptr = context->memblock;
    printf("loading in 64 bit\n");
    
    struct mach_header_64 header = *((struct mach_header_64 *)context->ptr);
    
    if (header.filetype != MH_EXECUTE) {
        return -1;
    }
    
    context->ptr += sizeof(struct mach_header_64);
    
    struct segment_command_64 command = *((struct segment_command_64 *)context->ptr);
    
    //--------
    int c_load_command = 0;
    
    while (c_load_command < header.ncmds) {
        int ptr_done = 0;
        command = *((struct segment_command_64 *)context->ptr);
        printf("Load command %d:0x%x, size:0x%x\n",c_load_command,command.cmd,command.cmdsize);
        if (command.cmd == LC_SEGMENT_64)
        {
            int n_section = load_segment_64(context);
            if (n_section != 0)
            {
                //SECTION
                //ptr += command.cmdsize;
                context->ptr += 0x48; //to only as far as the end of the segment header
                c_load_command++;
                ptr_done = 1;
                
                int c_load_section = 0;
                
                while (c_load_section < n_section) {
                    load_section_64(context);
                    context->ptr += sizeof(struct section_64);
                    c_load_section++;
                }
            }
        }else if((command.cmd & 0xFF) == LC_DYLD_INFO)
        {
            printf("+++DYLD_INFO+++\n");
            //dyld_info_command
            struct dyld_info_command dyld_info = *((struct dyld_info_command *)context->ptr);
            printf("binding info is at 0x%x, size:0x%x\n",dyld_info.bind_off,dyld_info.bind_size);
            
            
            //------------- BIND------------------
            
            uint8_t* start = context->memblock + dyld_info.bind_off;
            uint8_t* end = &start[dyld_info.bind_size];
            
            bind_list_retriever(context, start, end);
            
            //------------- LAZY BIND------------------
            
            start = context->memblock + dyld_info.lazy_bind_off;
            end = &start[dyld_info.lazy_bind_size];
            
            bind_list_retriever(context, start, end);
            
            
        }else if(command.cmd == LC_SYMTAB)
        {
            printf("+++SYMTAB+++\n");
            struct symtab_command symtab = *((struct symtab_command *)context->ptr);
            printf("syntab is at 0x%x, there are %d symbols and strtab is at:0x%x\n",symtab.symoff,symtab.nsyms,symtab.stroff);
            int c_str = 0;
            for (int c_sym = 0; c_sym < symtab.nsyms; c_sym++) {
                struct nlist_64 nlist = *((struct nlist_64 *)(context->memblock + symtab.symoff + (sizeof(struct nlist_64) * c_sym)));
                char* symbol = (char *)(context->memblock + symtab.stroff + nlist.n_un.n_strx);
                
                if (MAL_VERBOSE_SYMTAB || !strcmp(symbol, "_main") || nlist.n_value == 0xffffffff00000000) {
                    printf("0x%llx -> %s %d\n",
                   (void *)nlist.n_value - context->v_addr,
                    symbol,
                    nlist.n_type);
                }
                if (!strcmp(symbol, "_main"))
                {
                    context->entry_point = (void *)nlist.n_value - context->v_addr + context->img_addr;
                }
                c_str += 1;
            }
        }else if(command.cmd == LC_DYSYMTAB)
        {
            printf("+++DYSYMTAB+++\n");
            struct dysymtab_command dysymtab = *((struct dysymtab_command *)context->ptr);
            printf("extrefsymoff is at 0x%x, iundefsym = %d and %d\n",dysymtab.extrefsymoff,dysymtab.iundefsym,dysymtab.nundefsym);
            
        }else if(command.cmd == LC_LOAD_DYLINKER)
        {
            printf("+++LOAD_DYLINKER+++\n");
        }else if(command.cmd == LC_LOAD_DYLIB)
        {
            //get the name of dylib
            printf("+++LOAD_DYLIB+++\n");
            struct dylib_command* lib = (struct dylib_command *)context->ptr;
            printf("%s\n", ((char* )lib + lib->dylib.name.offset));
            dylib_list_retriever(context, ((char* )lib + lib->dylib.name.offset));
        } else if (command.cmd == LC_DYLD_CHAINED_FIXUPS) {
            printf("+++DYLD_CHAINED_FIXUPS+++\n");

            struct linkedit_data_command* fixups =
                (struct linkedit_data_command*)context->ptr;

            printf("fixups dataoff=0x%x datasize=0x%x\n",
                   fixups->dataoff,
                   fixups->datasize);

            dump_chained_fixups(context, fixups->dataoff, fixups->datasize);

        }else if(command.cmd == LC_DYLD_EXPORTS_TRIE)
        {
            printf("+++DYLD_EXPORTS_TRIE+++\n");

            struct linkedit_data_command* exports =
                (struct linkedit_data_command*)context->ptr;

            printf("exports dataoff=0x%x datasize=0x%x\n",
                   exports->dataoff,
                   exports->datasize);
        }else{
            printf("0x%lx----------cmd:0x%x--------\n", context->ptr - context->memblock, command.cmd);
        }
        
        if(!ptr_done)
        {
            context->ptr += command.cmdsize;
            c_load_command++;
        }
        
    }
    
    //printf("cmd:0x%x, size:0x%x\n",command.cmd,command.cmdsize);
    
    return 0;
}

int loader(mach_context* context)
{
    printf("loading in 32 bit (not implemented)\n");
    context->ptr = context->memblock;
    
    struct mach_header header = *((struct mach_header *)context->ptr);
    
    if (header.filetype != MH_EXECUTE) {
        return -1;
    }
    
    context->ptr += sizeof(struct mach_header);
    
    struct segment_command command = *((struct segment_command *)context->ptr);
    
    //--------
    int c_load_command = 0;
    
    while (c_load_command < header.ncmds) {
        int ptr_done = 0;
        command = *((struct segment_command *)context->ptr);
        printf("Load command %d:0x%x, size:0x%x\n",c_load_command,command.cmd,command.cmdsize);
        if (command.cmd == LC_SEGMENT)
        {
            int n_section = load_segment(context);
            if (n_section != 0)
            {
                //SECTION
                //ptr += command.cmdsize;
                context->ptr += sizeof(struct segment_command); //to only as far as the end of the segment header
                c_load_command++;
                ptr_done = 1;
                
                int c_load_section = 0;
                
                while (c_load_section < n_section) {
                    load_section(context);
                    context->ptr += sizeof(struct section);
                    c_load_section++;
                }
            }
        }else if((command.cmd & 0xFF) == LC_DYLD_INFO)
        {
            printf("+++DYLD_INFO+++\n");
            //dyld_info_command
            struct dyld_info_command dyld_info = *((struct dyld_info_command *)context->ptr);
            printf("binding info is at 0x%x, size:0x%x\n",dyld_info.bind_off,dyld_info.bind_size);
            
            
            //------------- BIND------------------
            
            uint8_t* start = context->memblock + dyld_info.bind_off;
            uint8_t* end = &start[dyld_info.bind_size];
            
            bind_list_retriever(context, start, end);
            
            //------------- LAZY BIND------------------
            
            start = context->memblock + dyld_info.lazy_bind_off;
            end = &start[dyld_info.lazy_bind_size];
            
            bind_list_retriever(context, start, end);
            
            
        }else if(command.cmd == LC_SYMTAB)
        {
            printf("+++SYMTAB+++\n");
            struct symtab_command symtab = *((struct symtab_command *)context->ptr);
            printf("syntab is at 0x%x, there are %d symbols and strtab is at:0x%x\n",symtab.symoff,symtab.nsyms,symtab.stroff);
            int c_str = 0;
            for (int c_sym = 0; c_sym < symtab.nsyms; c_sym++) {
                struct nlist nlist = *((struct nlist *)(context->memblock + symtab.symoff + (sizeof(struct nlist) * c_sym)));
                char* symbol = (char *)(context->memblock + symtab.stroff + nlist.n_un.n_strx);
                
                printf("0x%lx -> %s %d\n", (void *)nlist.n_value - context->v_addr, symbol, nlist.n_type);
                if (!strcmp(symbol, "_main"))
                {
                    context->entry_point =
                         (mach_main_entry_t)((uint8_t *)context->img_addr +
                                            ((uintptr_t)nlist.n_value -
                                             (uintptr_t)context->v_addr));
                }
                c_str += 1;
            }
        }else if(command.cmd == LC_DYSYMTAB)
        {
            printf("+++DYSYMTAB+++\n");
            struct dysymtab_command dysymtab = *((struct dysymtab_command *)context->ptr);
            printf("extrefsymoff is at 0x%x, iundefsym = %d and %d\n",dysymtab.extrefsymoff,dysymtab.iundefsym,dysymtab.nundefsym);
            
        }else if(command.cmd == LC_LOAD_DYLINKER)
        {
            printf("+++LOAD_DYLINKER+++\n");
        }else if(command.cmd == LC_LOAD_DYLIB)
        {
            //get the name of dylib
            printf("+++LOAD_DYLIB+++\n");
            struct dylib_command* lib = (struct dylib_command *)context->ptr;
            printf("%s\n", ((char* )lib + lib->dylib.name.offset));
            dylib_list_retriever(context, ((char* )lib + lib->dylib.name.offset));
        }else{
            printf("0x%lx----------cmd:0x%x--------\n", context->ptr - context->memblock, command.cmd);
        }
        
        if(!ptr_done)
        {
            context->ptr += command.cmdsize;
            c_load_command++;
        }
        
    }
    return -1;
}

int main(int argc, char *argv[])
{
    //get filename
    if(argv[1] == NULL)
        return -1;
    char* filename = argv[1];
    printf("%s\n",filename);
    
    mach_context c = {0};
    mach_context* context = &c;
    context->argc = argc - 1;
    context->argv = &argv[1];
    context->memblock = openExec(filename);
    context->bit = determineBit(context->memblock);
    context->b_list.n_bind_info = 0;
    context->d_list.n_dylib_info = 0;
    context->n_segment_info = 0;
    
    
    typedef int (*mach_loader)(mach_context*);
    mach_loader l[2]={loader,loader_64};
    
    int loader_result = l[(context->bit) >> 6](context);
    if (loader_result != 0) {
        fprintf(stderr,
                "maloader: loader failed for %s (%d-bit), result=%d\n",
                filename,
                context->bit,
                loader_result);
        //return 1;
    }

    if (context->img_addr == NULL || context->v_addr == NULL) {
        fprintf(stderr,
                "maloader: image mapping was not established "
                "(img_addr=%p, v_addr=%p)\n",
                context->img_addr,
                context->v_addr);
        //return 1;
    }

    if (context->entry_point == NULL) {
        fprintf(stderr, "maloader: no entry point found\n");
        //return 1;
    }

    if (context->chained_unresolved_bind_count != 0) {
        fprintf(stderr,
                "maloader: unresolved chained binds: %u\n",
                context->chained_unresolved_bind_count);
        //return 1;
    }
    
    
    int bind_result = do_bind(context);
    if (bind_result != 0) {
        fprintf(stderr,
                "maloader: bind failed, result=%d\n",
                bind_result);
        //return 1;
    }
    
    printf("now to exec from %p\n", (void *)context->entry_point);
    int result = context->entry_point(context->argc, context->argv);
    printf("result=%d\n",result);
    return 0;
}
