#include "bind.h"
#ifndef	_MACH_CTRL_H_
#define _MACH_CTRL_H_

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include "mach-o/loader.h"
#include "mach-o/nlist.h"



typedef struct  {
    char*   dylib_name;
    //void*   address;
} dylib_info;

typedef struct  {
    int             n_dylib_info;
    dylib_info*      info;
} dylib_list;

typedef struct  {
    void*   memblock;//where the mapped objectfile is.
    void*   ptr;    //current read out;
    void*   img_addr;//executable on memory
    void*    v_addr;//virtual address that was found in the binary
    void*   entry_point;
    bind_list b_list;
    dylib_list d_list;
    int argc;
    char **argv;
    int bit;
} mach_context;

void* openExec(char* filename);
int determineBit(void* mach_header);

void print_segment_64(struct segment_command_64 lc_segment);

#if defined(__x86_64__) || defined(__LP64__)
uint64_t alignMemory(uint64_t pointer, uint64_t alignment);
#else
uint32_t alignMemory(uint32_t pointer, uint32_t alignment);
#endif
int load_segment_64(mach_context* context);


int load_section_64(mach_context* context);

int dylib_list_retriever(mach_context* context, char *dylib_name);

int loader_64(mach_context* context);
int loader(mach_context* context);
#endif	/* _MACH_CTRL_H_ */
