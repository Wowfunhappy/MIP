#include "injected.h"
#include <mach-o/dyld_images.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <string.h>
#include <dlfcn.h>

/* These values are overwritten on a per-injection basis by the injector */
/* Must not be defined as consts, or the compiler will optimize them. */
__attribute__((section("__TEXT,__const"))) struct dyld_all_image_infos *dyld_info = (typeof(dyld_info)) DYLD_MAGIC_64;

__attribute__((section("__TEXT,__const"))) char argument[ARGUMENT_MAX_LENGTH] = ARGUMENT_MAGIC_STR;

/* The preserve_all calling convention does not save the flags register, so we use
   these ASM functions to save and restore it outselves. They must be called as
   early and as late as possible, respectively, so instructions that modify flags
   won't destory the state. */

static const struct mach_header_64 *get_header_by_path(const char *name)
{
    for (unsigned i = 0; i < dyld_info->infoArrayCount; i++) {
        if (strcmp(dyld_info->infoArray[i].imageFilePath, name) == 0) {
            return (const struct mach_header_64 *) dyld_info->infoArray[i].imageLoadAddress;
        }
    }
    return NULL;
}

static const void *get_symbol_from_header(const struct mach_header_64 *header, const char *symbol)
{
    if (!header) {
        return NULL;
    }
    
    /* Get the required commands */
    
    const struct symtab_command *symtab = NULL;
    const struct segment_command_64 *first = NULL;
    const struct segment_command_64 *linkedit = NULL;
    const struct load_command *cmd = (typeof(cmd))(header + 1);
    
    for (unsigned i = 0; i < header->ncmds; i++, cmd = (typeof(cmd)) ((char*) cmd + cmd->cmdsize)) {
        if (cmd->cmd == LC_SEGMENT_64) {
            if (!first && ((typeof(first))cmd)->filesize ) {
                first = (typeof(first)) cmd;
            }
            if (strcmp(((typeof(linkedit)) cmd)->segname, "__LINKEDIT") == 0) {
                linkedit = (typeof(linkedit)) cmd;
            }
        }
        else if (cmd->cmd == LC_SYMTAB) {
            symtab = (typeof (symtab)) cmd;
        }
        if (symtab && linkedit) break;
    }
    
    if (!symtab || !linkedit) return NULL;
    
    const char *string_table =
        ((const char *) header + symtab->stroff - linkedit->fileoff + linkedit->vmaddr - first->vmaddr);
    const struct nlist_64 *symbols = (typeof (symbols))
        ((const char *) header + symtab->symoff - linkedit->fileoff + linkedit->vmaddr - first->vmaddr);
    
    for (unsigned i = 0; i < symtab->nsyms; i++) {
        if (strcmp(string_table + symbols[i].n_un.n_strx, symbol) == 0) {
            return (char *)header + symbols[i].n_value - first->vmaddr;
        }
    }
    
    return NULL;
}

#ifdef ROSETTA
void __attribute__((naked)) late_inject(void)
{
    __asm__ ("push %rsp\n"
             "push %r11\n"
             "pushfq\n"
             "call _c_late_inject\n"
             "popfq\n"
             "pop %r11\n"
             "ret");
}

/* In Rosetta, __TEXT segments are RWX, so we can put our data in __TEXT,
   and to properly generate payloads, everything must be in one segment. */
static __attribute__((section("__TEXT,__data"))) uintptr_t *stack_ret = NULL;
static __attribute__((section("__TEXT,__data"))) uintptr_t ret_address = 0;

void __attribute__((preserve_all)) c_late_inject(void)
{
    *stack_ret = ret_address;
    typeof(dlopen) *$dlopen = NULL;
    $dlopen = get_symbol_from_header(get_header_by_path("/usr/lib/system/libdyld.dylib"), "_dlopen");
    
    if ($dlopen) {
        $dlopen(argument, RTLD_NOW);
    }
}
#endif

/* Called by `entry` below with all caller-saved state already preserved, so
   this can be ordinary C. */
void c_entry(void)
{
    typeof(dlopen) *$dlopen = NULL;

    /* We can't call dyld`dlopen when dyld3 is being used, so we must find libdyld`dlopen and call that instead */
    $dlopen = get_symbol_from_header(get_header_by_path("/usr/lib/system/libdyld.dylib"), "_dlopen");
    
    if ($dlopen) {
        $dlopen(argument, RTLD_NOW);
    }
}

/* Mavericks port: the clang shipped for 10.9 (Xcode 6) does not implement the
   preserve_all calling convention, so the entry point saves every caller-saved
   register (and the flags) by hand before calling into C.

   On entry the stack is as if `entry` had been called: rsp % 16 == 8. */
void __attribute__((naked)) entry(void)
{
    __asm__ ("pushfq\n"                  // rsp % 16 == 0
             "push %rax\n"
             "push %rcx\n"
             "push %rdx\n"
             "push %rsi\n"
             "push %rdi\n"
             "push %r8\n"
             "push %r9\n"
             "push %r10\n"
             "push %r11\n"                // 9 pushes: rsp % 16 == 8
             "sub $264, %rsp\n"           // 16 xmm registers + 8 for alignment
             "movdqu %xmm0, 0(%rsp)\n"
             "movdqu %xmm1, 16(%rsp)\n"
             "movdqu %xmm2, 32(%rsp)\n"
             "movdqu %xmm3, 48(%rsp)\n"
             "movdqu %xmm4, 64(%rsp)\n"
             "movdqu %xmm5, 80(%rsp)\n"
             "movdqu %xmm6, 96(%rsp)\n"
             "movdqu %xmm7, 112(%rsp)\n"
             "movdqu %xmm8, 128(%rsp)\n"
             "movdqu %xmm9, 144(%rsp)\n"
             "movdqu %xmm10, 160(%rsp)\n"
             "movdqu %xmm11, 176(%rsp)\n"
             "movdqu %xmm12, 192(%rsp)\n"
             "movdqu %xmm13, 208(%rsp)\n"
             "movdqu %xmm14, 224(%rsp)\n"
             "movdqu %xmm15, 240(%rsp)\n"
             "call _c_entry\n"
             "movdqu 0(%rsp), %xmm0\n"
             "movdqu 16(%rsp), %xmm1\n"
             "movdqu 32(%rsp), %xmm2\n"
             "movdqu 48(%rsp), %xmm3\n"
             "movdqu 64(%rsp), %xmm4\n"
             "movdqu 80(%rsp), %xmm5\n"
             "movdqu 96(%rsp), %xmm6\n"
             "movdqu 112(%rsp), %xmm7\n"
             "movdqu 128(%rsp), %xmm8\n"
             "movdqu 144(%rsp), %xmm9\n"
             "movdqu 160(%rsp), %xmm10\n"
             "movdqu 176(%rsp), %xmm11\n"
             "movdqu 192(%rsp), %xmm12\n"
             "movdqu 208(%rsp), %xmm13\n"
             "movdqu 224(%rsp), %xmm14\n"
             "movdqu 240(%rsp), %xmm15\n"
             "add $264, %rsp\n"
             "pop %r11\n"
             "pop %r10\n"
             "pop %r9\n"
             "pop %r8\n"
             "pop %rdi\n"
             "pop %rsi\n"
             "pop %rdx\n"
             "pop %rcx\n"
             "pop %rax\n"
             "popfq\n"
             "ret\n");
}


/* Taken from Apple's libc */

int strcmp(const char *s1, const char *s2)
{
    while (*s1 == *s2++)
        if (*s1++ == 0)
            return (0);
    return (*(const unsigned char *)s1 - *(const unsigned char *)(s2 - 1));
}
