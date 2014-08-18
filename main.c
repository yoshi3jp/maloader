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
#if __x86_64__
uint64_t alignMemory(uint64_t pointer, uint64_t alignment) {
#else
uint32_t alignMemory(uint32_t pointer, uint32_t alignment) {
#endif
    alignment--;
    return (pointer + alignment) & ~alignment;
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
    return lc_segment.nsects;
}

int load_segment_64(mach_context* context)
{
    struct segment_command_64 lc_segment = *((struct segment_command_64 *)context->ptr);
    print_segment_64(lc_segment);
    //__TEXT
    if (!strcmp(lc_segment.segname, SEG_TEXT)) {
        printf("++++++++++++++++++\n");
        uint64_t filesize = alignMemory(lc_segment.filesize + 0x3000, 0x1000);
        //uint64_t vmsize = alignMemory(lc_segment.filesize, 0x1000);
        printf("Allocating 0x%llxbytes at 0x%llx\n",filesize,lc_segment.vmaddr);
        void* vm_segment = mmap((void*)lc_segment.vmaddr, filesize, PROT_READ | PROT_WRITE | PROT_EXEC , MAP_ANON | MAP_SHARED, -1, 0);
        if (vm_segment == MAP_FAILED) {
            printf("Failed mapping %s\n",lc_segment.segname);
        }
        memcpy(vm_segment, context->memblock, lc_segment.filesize);
        
        //int (*fp)(int argc, char *argv[]) = vm_segment;
        //(*fp)(0,NULL);
        context->img_addr = vm_segment;
        context->v_addr = lc_segment.vmaddr;
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
                
                printf("0x%llx -> %s %d\n", (void *)nlist.n_value - context->v_addr, symbol, nlist.n_type);
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
    
    mach_context c;
    mach_context* context = &c;
    context->argc = argc - 1;
    context->argv = &argv[1];
    context->memblock = openExec(filename);
    context->bit = determineBit(context->memblock);
    context->b_list.n_bind_info = 0;
    context->d_list.n_dylib_info = 0;
    
    
    
    typedef int (*mach_loader)(mach_context*);
    mach_loader l[2]={loader,loader_64};
    
    l[(context->bit) >> 6](context);
    
    do_bind(context);
    
    int (*fp)(int, char **) = (void *)context->entry_point;
    printf("now to exec from 0x%lx\n", fp);
    int result = fp(context->argc,context->argv);
    printf("result=%d\n",result);
    return 0;
}
