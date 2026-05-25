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

#include "machctrl.h"
#include "bind.h"

#ifdef __linux__
#include <stdint.h>

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

#define DARWIN_MAP_ANON 0x1000

extern char **environ;

static FILE* mal_stdinp;
static FILE* mal_stdoutp;
static FILE* mal_stderrp;
static uintptr_t mal_stack_chk_guard = 0x6d616c6f61646572ULL;

static void* host_mmap_for_darwin(void* addr,
                                  size_t length,
                                  int prot,
                                  int flags,
                                  int fd,
                                  off_t offset)
{
    int host_flags = flags;

    if (flags & DARWIN_MAP_ANON) {
        host_flags &= ~DARWIN_MAP_ANON;
        host_flags |= MAP_ANONYMOUS;
    }

    return mmap(addr, length, prot, host_flags, fd, offset);
}
#endif


void print_bind_list(bind_list* list)
{
    printf("--- bind list ---\n");
    for (int i = 0; i < list->n_bind_info; i++) {
        printf("%s, 0x%llx\n", list->info[i].func_name, list->info[i].address);
    }
    printf("---           ---\n");
}

static int* mal_darwin_error(void)
{
    return &errno;
}

static char*** mal_NSGetEnviron(void)
{
    return &environ;
}

static void mal_chkstk_darwin(void)
{
    /* no-op for this loader experiment */
}

static int mal_darwin_check_fd_set_overflow(int fd, const void* set, int write)
{
    (void)fd;
    (void)set;
    (void)write;
    return 0;
}

static void mal_memset_pattern16(void* dst, const void* pattern16, size_t len)
{
    uint8_t* d = dst;
    const uint8_t* p = pattern16;

    for (size_t i = 0; i < len; i++) {
        d[i] = p[i & 15];
    }
}

static void* open_host_libc(void)
{
    static void* libc_handle;

    if (!libc_handle) {
        libc_handle = dlopen("libc.so.6", RTLD_LAZY | RTLD_GLOBAL);
        if (!libc_handle) {
            printf("dlopen(libc.so.6) failed: %s\n", dlerror());
        }
    }

    return libc_handle;
}

static void normalize_macho_symbol_name(const char* macho_name,
                                        char* out,
                                        size_t out_size)
{
    const char* c = macho_name ? macho_name : "";

    if (c[0] == '_') {
        c++;
    }

    snprintf(out, out_size, "%s", c);

    /*
     * Darwin suffixes such as:
     *   _realpath$DARWIN_EXTSN
     *   _syslog$DARWIN_EXTSN
     */
    char* suffix = strchr(out, '$');
    if (suffix) {
        *suffix = '\0';
    }
}

static void* resolve_macho_import_symbol(const char* macho_name)
{
    char namebuf[256];

    if (!macho_name) {
        return NULL;
    }

    normalize_macho_symbol_name(macho_name, namebuf, sizeof(namebuf));

    if (!strcmp(namebuf, "__NSGetEnviron")) {
        return mal_NSGetEnviron;
    }

    if (!strcmp(namebuf, "__error")) {
        return mal_darwin_error;
    }

    if (!strcmp(namebuf, "__stack_chk_guard")) {
        return &mal_stack_chk_guard;
    }

    if (!strcmp(namebuf, "__stdinp")) {
        mal_stdinp = stdin;
        return &mal_stdinp;
    }

    if (!strcmp(namebuf, "__stdoutp")) {
        mal_stdoutp = stdout;
        return &mal_stdoutp;
    }

    if (!strcmp(namebuf, "__stderrp")) {
        mal_stderrp = stderr;
        return &mal_stderrp;
    }

    if (!strcmp(namebuf, "__chkstk_darwin")) {
        return mal_chkstk_darwin;
    }

    if (!strcmp(namebuf, "__darwin_check_fd_set_overflow")) {
        return mal_darwin_check_fd_set_overflow;
    }

    if (!strcmp(namebuf, "memset_pattern16")) {
        return mal_memset_pattern16;
    }

    void* libc = open_host_libc();
    if (!libc) {
        return NULL;
    }

    return dlsym(libc, namebuf);
}

int apply_chained_bind(mach_context* context,
                       void* loc,
                       const char* symbol_name,
                       int64_t addend)
{
    void* resolved = resolve_macho_import_symbol(symbol_name);

    context->chained_bind_count++;

    if (!resolved) {
        printf("      unresolved chained import: %s\n",
               symbol_name ? symbol_name : "(null)");
        context->chained_unresolved_bind_count++;
        return -1;
    }

    uint64_t final = (uint64_t)(uintptr_t)resolved + addend;

#if 0
    printf("      APPLY bind loc=%p symbol=%s resolved=%p addend=%lld final=0x%llx\n",
           loc,
           symbol_name,
           resolved,
           (long long)addend,
           final);
#endif

    *(uint64_t*)loc = final;
    return 0;
}

static void guard(void)
{
	__stack_chk_guard[0] = 1;
}

int do_bind(mach_context* context)
{
    
    
    /*
	default libs
    libc
    libm
*/
    //dylib_list_retriever(context, "/lib/x86_64-linux-gnu/libc-2.15.so");
    dylib_list_retriever(context, "libc.so.6");
    dylib_list_retriever(context, "libm.so.6");
    
    printf("loading dylib...\n");
    for (int i = 0; i < context->d_list.n_dylib_info; i++) {
        printf("%s\n", context->d_list.info[i].dylib_name);
        void* library = dlopen(context->d_list.info[i].dylib_name, RTLD_LAZY);
        if (library == NULL) {
            printf("lib not loaded\n");
        } else {
            printf("binding...\n");
            for (int j = 0; j < context->b_list.n_bind_info; j++) {
                printf("%s, 0x%llx\n", context->b_list.info[j].func_name, context->b_list.info[j].address);
                if (context->b_list.info[j].address <= context->img_addr) {
                    //ToDo: make this if statement more reasonable.
printf("Function [%s] was not binded for it seemed unfit.\n", context->b_list.info[j].func_name);
                    continue;
                }

                char* c = context->b_list.info[j].func_name;
                if (c[0] == '_') {
                    c++;
                }
                #ifdef __linux__
                if (!strcmp(c, "mmap")) {
                    printf("using Darwin mmap wrapper\n");
                    ptrval* func_dest = context->b_list.info[j].address;
                    *func_dest = (ptrval)host_mmap_for_darwin;
                    continue;
                }
                #endif
                if(!strcmp(c, "__stack_chk_guard"))
                {
                    printf("stack_chk_guard (supress error) 0x%llx\n",context->b_list.info[j].address);
                    //unsigned long __stack_chk_guard = 0;
                    ptrval* func_dest = context->b_list.info[j].address;
                    *func_dest = guard;
                    continue;
                }

                ptrval* initializer = (void *)dlsym(library, c);
                if (initializer == (ptrval) NULL) {
                    printf("func not loaded\n");
                } else {
                    printf("func addr = 0x%llx\n",initializer);
                    
                    ptrval* func_dest = context->b_list.info[j].address;
                    
                    *func_dest = initializer;
                }
                
            }
        }
    }
    
    
    return 0;
    
}

static uint64_t read_uleb128(const uint8_t** pp, const uint8_t* end)
{
    const uint8_t* p = *pp;
    uint64_t result = 0;
    int bit = 0;

    while (p < end) {
        uint8_t byte = *p++;
        result |= ((uint64_t)(byte & 0x7f)) << bit;

        if ((byte & 0x80) == 0) {
            break;
        }

        bit += 7;
    }

    *pp = p;
    return result;
}

static void append_bind_info(mach_context* context, char* func_name, void* address)
{
    if (context->b_list.n_bind_info == 0 && context->b_list.info == NULL) {
        printf("First pass of BIND\n");
        context->b_list.info = malloc(sizeof(bind_info));
    } else {
        context->b_list.info = realloc(context->b_list.info,
                                       sizeof(bind_info) *
                                       (context->b_list.n_bind_info + 1));
    }

    context->b_list.info[context->b_list.n_bind_info].func_name = func_name;
    context->b_list.info[context->b_list.n_bind_info].address = address;
    context->b_list.n_bind_info++;
}

static void* bind_address_for_segment_offset(mach_context* context,
                                             int segment_index,
                                             uint64_t offset)
{
    if (segment_index < 0 || segment_index >= context->n_segment_info) {
        printf("bad bind segment index %d\n", segment_index);
        return NULL;
    }

    segment_info* seg = &context->segments[segment_index];

    if (seg->mapped_addr == NULL) {
        printf("bind target segment %d (%s) is not mapped\n",
               segment_index,
               seg->segname);
        return NULL;
    }

    return seg->mapped_addr + offset;
}

int bind_list_retriever(mach_context* context, const uint8_t* const start, const uint8_t* const end)
{
    printf("bind_list_retriever\n");

    const uint8_t* p = start;

    char* symbol_name = NULL;
    int segment_index = -1;
    uint64_t segment_offset = 0;
    const uint64_t pointer_size = sizeof(ptrval);

    while (p < end) {
        uint8_t byte = *p++;
        uint8_t opcode = byte & BIND_OPCODE_MASK;
        uint8_t immediate = byte & BIND_IMMEDIATE_MASK;

        switch (opcode) {
            case BIND_OPCODE_DONE:
                /*
                 * In lazy-bind info, DONE terminates one lazy-bind record,
                 * but more records may follow.  Do not stop the whole parser.
                 */
                break;

            case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
                break;

            case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
                (void)read_uleb128(&p, end);
                break;

            case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
                break;

            case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
                symbol_name = (char*)p;
                p += strlen(symbol_name) + 1;
                break;

            case BIND_OPCODE_SET_TYPE_IMM:
                break;

            case BIND_OPCODE_SET_ADDEND_SLEB:
                /*
                 * This loader does not use addends yet.
                 * For now, consume it like ULEB enough for this old test path.
                 */
                (void)read_uleb128(&p, end);
                break;

            case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
                segment_index = immediate;
                segment_offset = read_uleb128(&p, end);
                break;

            case BIND_OPCODE_ADD_ADDR_ULEB:
                segment_offset += read_uleb128(&p, end);
                break;

            case BIND_OPCODE_DO_BIND: {
                void* address = bind_address_for_segment_offset(context,
                                                                segment_index,
                                                                segment_offset);
                append_bind_info(context, symbol_name, address);
                segment_offset += pointer_size;
                break;
            }

            case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB: {
                void* address = bind_address_for_segment_offset(context,
                                                                segment_index,
                                                                segment_offset);
                append_bind_info(context, symbol_name, address);
                segment_offset += pointer_size;
                segment_offset += read_uleb128(&p, end);
                break;
            }

            case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED: {
                void* address = bind_address_for_segment_offset(context,
                                                                segment_index,
                                                                segment_offset);
                append_bind_info(context, symbol_name, address);
                segment_offset += pointer_size + (immediate * pointer_size);
                break;
            }

            case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: {
                uint64_t count = read_uleb128(&p, end);
                uint64_t skip = read_uleb128(&p, end);

                for (uint64_t i = 0; i < count; i++) {
                    void* address = bind_address_for_segment_offset(context,
                                                                    segment_index,
                                                                    segment_offset);
                    append_bind_info(context, symbol_name, address);
                    segment_offset += pointer_size + skip;
                }
                break;
            }

            default:
                printf("unknown bind opcode 0x%x\n", opcode);
                break;
        }
    }

    return 0;
}
