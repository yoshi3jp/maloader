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


void print_bind_list(bind_list* list)
{
    printf("--- bind list ---\n");
    for (int i = 0; i < list->n_bind_info; i++) {
        printf("%s, 0x%llx\n", list->info[i].func_name, list->info[i].address);
    }
    printf("---           ---\n");
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
dylib_list_retriever(context, "/lib/i386-linux-gnu/libc.so.6");
    
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

int bind_list_retriever(mach_context* context, const uint8_t* const start, const uint8_t* const end)
{
    printf("bind_list_retriever\n");
    if(!(context->b_list.n_bind_info != 0))
    {
        printf("First pass of BIND\n");
        context->b_list.info = malloc(sizeof(bind_info));
    }
    
    const uint8_t* p = start;
    int done = 0;
    
    
    while ( !done && (p < end) )
    {
        uint8_t opcode = *p & BIND_OPCODE_MASK;
        //printf("opcode = 0x%x\n",opcode);
        //++p;
        switch (opcode) {
            case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
                context->b_list.info[context->b_list.n_bind_info].func_name = (char*)p+1;
                //printf("detected %s\n",context->b_list.info[context->b_list.n_bind_info].func_name);
                while (*p != '\0')
                    ++p;
                ++p;
                break;
            case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
                //printf("ULEB, 0x%x\n",*(p+1));
                context->b_list.info[context->b_list.n_bind_info].address = *(p+1) + context->img_addr + 0x1000;
                //printf("addr = 0x%llx\n",context->b_list.info[context->b_list.n_bind_info].address);
                ++p;
                break;
            case BIND_OPCODE_DO_BIND: //end of one bind prepare for next
                //printf("DO_BIND\n");
                context->b_list.n_bind_info ++; //increment count of bindings
                context->b_list.info = realloc(context->b_list.info,sizeof(bind_info) * (context->b_list.n_bind_info + 1));//make more space
                ++p;
                break;
            default:
                ++p;
        }
    }
    
    //print_bind_list(&(context->b_list));
    
    return 0;
}
