#ifndef	_BIND_H_
#define _BIND_H_

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

#if defined(__x86_64__) || defined(__LP64__)
#define ptrval uint64_t
#else
#define ptrval uint32_t
#endif
typedef struct  {
    char*   func_name;
    void*   address;
} bind_info;

typedef struct  {
    int             n_bind_info;
    bind_info*      info;
} bind_list;

#include "machctrl.h"

void print_bind_list(bind_list* list);

static long __stack_chk_guard[8] = {0,0,0,0,0,0,0,0};
static void guard(void);

int do_bind(mach_context* context);

int apply_chained_bind(mach_context* context, void* loc, const char* symbol_name, int64_t addend);

int bind_list_retriever(mach_context* context, const uint8_t* const start, const uint8_t* const end);
#endif	/* _BIND_H_ */
