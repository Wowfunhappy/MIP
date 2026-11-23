#include "injected.h"
#include <mach-o/dyld_images.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <string.h>
#include <dlfcn.h>

/* These values are overwritten on a per-injection basis by the injector. */
/* Must not be defined as consts, or the compiler will optimize them. */
__attribute__((section("__TEXT,__const"))) struct dyld_all_image_infos *dyld_info = (typeof(dyld_info)) DYLD_MAGIC_32;

__attribute__((section("__TEXT,__const"))) char argument[ARGUMENT_MAX_LENGTH] = ARGUMENT_MAGIC_STR;

static const struct mach_header *get_header_by_path(const char *name)
{
    for (unsigned i = 0; i < dyld_info->infoArrayCount; i++) {
        if (strcmp(dyld_info->infoArray[i].imageFilePath, name) == 0) {
            return (const struct mach_header *) dyld_info->infoArray[i].imageLoadAddress;
        }
    }
    return NULL;
}

static const void *get_symbol_from_header(const struct mach_header *header, const char *symbol)
{
    if (!header) {
        return NULL;
    }
    
    /* Get the required commands */
    
    const struct symtab_command *symtab = NULL;
    const struct segment_command *first = NULL;
    const struct segment_command *linkedit = NULL;
    const struct load_command *cmd = (typeof(cmd))(header + 1);
    
    for (unsigned i = 0; i < header->ncmds; i++, cmd = (typeof(cmd)) ((char*) cmd + cmd->cmdsize)) {
        if (cmd->cmd == LC_SEGMENT) {
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
    const struct nlist *symbols = (typeof (symbols))
        ((const char *) header + symtab->symoff - linkedit->fileoff + linkedit->vmaddr - first->vmaddr);
    
    for (unsigned i = 0; i < symtab->nsyms; i++) {
        if (strcmp(string_table + symbols[i].n_un.n_strx, symbol) == 0) {
            return (char *)header + symbols[i].n_value - first->vmaddr;
        }
    }
    
    return NULL;
}


void c_entry(void)
{
    typeof(dlopen) *$dlopen = NULL;
    
    /* We can't call dyld`dlopen when dyld3 is being used, so we must find libdyld`dlopen and call that instead */
    $dlopen = get_symbol_from_header(get_header_by_path("/usr/lib/system/libdyld.dylib"), "_dlopen");
    
    if ($dlopen) {
        $dlopen(argument, RTLD_NOW);
    }
}

/* Mavericks port: Xcode 6's clang has no x86-32 interrupt attribute, so the
   entry point saves all general purpose, SSE and flags state by hand, aligns
   the stack for the C call, and restores everything afterwards. */
void __attribute__((naked)) entry(void)
{
    __asm__ ("pushfl\n"
             "pushal\n"
             "movl %esp, %ebp\n"        // ebp is restored by popal
             "subl $128, %esp\n"
             "andl $-16, %esp\n"
             "movdqu %xmm0, 0(%esp)\n"
             "movdqu %xmm1, 16(%esp)\n"
             "movdqu %xmm2, 32(%esp)\n"
             "movdqu %xmm3, 48(%esp)\n"
             "movdqu %xmm4, 64(%esp)\n"
             "movdqu %xmm5, 80(%esp)\n"
             "movdqu %xmm6, 96(%esp)\n"
             "movdqu %xmm7, 112(%esp)\n"
             "call _c_entry\n"
             "movdqu 0(%esp), %xmm0\n"
             "movdqu 16(%esp), %xmm1\n"
             "movdqu 32(%esp), %xmm2\n"
             "movdqu 48(%esp), %xmm3\n"
             "movdqu 64(%esp), %xmm4\n"
             "movdqu 80(%esp), %xmm5\n"
             "movdqu 96(%esp), %xmm6\n"
             "movdqu 112(%esp), %xmm7\n"
             "movl %ebp, %esp\n"
             "popal\n"
             "popfl\n"
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