#include <xpc/xpc.h>
#include <bsm/libbsm.h>
#include <libproc.h>
#include <stdint.h>
#include <pwd.h>
#include <sys/syslimits.h>
#include <dlfcn.h>
#include <mach-o/loader.h>
#include <mach-o/dyld.h>
#include "injectd_client/injectd_client.h"
#include <stdbool.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <stdio.h>

// Private APIs
extern mach_port_t xpc_dictionary_copy_mach_send(xpc_object_t, const char *);
extern void xpc_dictionary_get_audit_token(xpc_object_t xdict, audit_token_t *token);

static const char *MIP_injector_path(void)
{
    Dl_info info;
    dladdr("", &info); // Get own info
    return info.dli_fname;
}

static const char *MIP_loader_path(void)
{
    static char *ret = NULL;
    if (ret) return ret;
    
    ret = strdup(MIP_injector_path());
    *strrchr(ret, '/') = 0;
    
    // strlen("loader.dylib") < strlen("lsdinjector.dylib")
    strcat(ret, "/loader.dylib");
    
    return ret;
}

static const char *MIP_root_path(void)
{
    static char *ret = NULL;
    if (ret) return ret;
    
    ret = strdup(MIP_injector_path());
    *strrchr(ret, '/') = 0;
    return ret;
}

/* Mavericks port: setuid/setgid processes (P_SUGID: what issetugid() reports
   in the process itself) are left alone, as dyld leaves them alone with
   DYLD_INSERT_LIBRARIES. Bundles have no business running with privileges the
   user doesn't have, and AppKit refuses to run in such processes: the first
   use of NSApplication or NSWindow logs "...is running setugid(), which is
   not allowed." and exits. A process like VMware Fusion's vmware-vmx (setuid
   root) links AppKit without using it, and a bundle loaded into it - any
   that touches NSWindow as it loads - kills it. The loader checks too. */
static bool process_is_setugid(pid_t pid)
{
    struct kinfo_proc info;
    size_t size = sizeof(info);
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, pid };
    if (sysctl(mib, 4, &info, &size, NULL, 0) != 0 || size == 0) return true;  /* unknown: leave it alone */
    return (info.kp_proc.p_flag & P_SUGID) != 0;
}

static void handleClientMessageHook_common(uint64_t command, xpc_object_t dict)
{
    /* Command 500 is sent by all GUI processes to launchservicesd when they launch.
       The process will block until it receives an answer from launchservicesd.
       We will inject our code before we send a reply. Once we send the actual reply,
       by calling the original method, the process resumes, runs the injected dlopen,
       and continues normal execution. */
    
    if (command == 500) {
        /* Mavericks port: kill switch. `sudo touch <MIP root>/disabled` stops
           all injection immediately, without restarting launchservicesd. */
        char disabled[PATH_MAX];
        snprintf(disabled, sizeof(disabled), "%s/disabled", MIP_root_path());
        if (access(disabled, F_OK) == 0) return;

        audit_token_t token;
        xpc_dictionary_get_audit_token(dict, &token);
        pid_t pid = audit_token_to_pid(token);
        if (process_is_setugid(pid)) return;

        inject_to_pid(pid, MIP_loader_path(), false);
    }
}

static uint64_t xpc_dictionary_get_int64_hook(xpc_object_t dict, const char *key)
{
    uint64_t ret = xpc_dictionary_get_int64(dict, key);
    if (strcmp(key, "command") == 0) {
        handleClientMessageHook_common(ret, dict);
    }
    return ret;
}

/* Mavericks port: upstream patches launchservicesd's own import of
   xpc_dictionary_get_int64. On 10.9 the server code that reads the "command"
   key (LSXPCClientConnection::handleMessage) lives in
   LaunchServices.framework instead, so rebind the import in every loaded image
   (fishhook-style, via each image's indirect symbol table), except our own. */

#include <mach-o/nlist.h>
#include <mach/mach.h>
#include <syslog.h>

static const struct mach_header_64 *own_header(void)
{
    Dl_info info;
    dladdr((void *)&xpc_dictionary_get_int64_hook, &info);
    return (const struct mach_header_64 *)info.dli_fbase;
}

static void make_writable(void **address)
{
    vm_address_t page = (vm_address_t)address & ~(vm_address_t)(PAGE_SIZE - 1);
    if (vm_protect(mach_task_self(), page, PAGE_SIZE, false, VM_PROT_READ | VM_PROT_WRITE) != KERN_SUCCESS) {
        vm_protect(mach_task_self(), page, PAGE_SIZE, false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    }
}

static void rebind_in_image(const struct mach_header *mh, intptr_t slide)
{
    const struct mach_header_64 *header = (const struct mach_header_64 *)mh;
    if (header->magic != MH_MAGIC_64 || header == own_header()) return;

    /* Only the image that serves check-ins: other libraries in launchservicesd
       may read unrelated "command" keys. */
    Dl_info image_info;
    if (!dladdr(mh, &image_info) || !image_info.dli_fname) return;
    const char *suffix = "/LaunchServices.framework/Versions/A/LaunchServices";
    size_t name_length = strlen(image_info.dli_fname), suffix_length = strlen(suffix);
    if (name_length < suffix_length || strcmp(image_info.dli_fname + name_length - suffix_length, suffix) != 0) return;

    const struct segment_command_64 *linkedit = NULL;
    const struct symtab_command *symtab = NULL;
    const struct dysymtab_command *dysymtab = NULL;
    const struct load_command *cmd = (const struct load_command *)(header + 1);
    for (unsigned i = 0; i < header->ncmds; i++, cmd = (const struct load_command *)((const char *)cmd + cmd->cmdsize)) {
        if (cmd->cmd == LC_SEGMENT_64 && strcmp(((const struct segment_command_64 *)cmd)->segname, SEG_LINKEDIT) == 0) {
            linkedit = (const struct segment_command_64 *)cmd;
        }
        else if (cmd->cmd == LC_SYMTAB) {
            symtab = (const struct symtab_command *)cmd;
        }
        else if (cmd->cmd == LC_DYSYMTAB) {
            dysymtab = (const struct dysymtab_command *)cmd;
        }
    }
    if (!linkedit || !symtab || !dysymtab || !dysymtab->nindirectsyms) return;

    uintptr_t linkedit_base = (uintptr_t)slide + linkedit->vmaddr - linkedit->fileoff;
    const struct nlist_64 *symbols = (const struct nlist_64 *)(linkedit_base + symtab->symoff);
    const char *strings = (const char *)(linkedit_base + symtab->stroff);
    const uint32_t *indirect = (const uint32_t *)(linkedit_base + dysymtab->indirectsymoff);

    cmd = (const struct load_command *)(header + 1);
    for (unsigned i = 0; i < header->ncmds; i++, cmd = (const struct load_command *)((const char *)cmd + cmd->cmdsize)) {
        if (cmd->cmd != LC_SEGMENT_64) continue;
        const struct segment_command_64 *segment = (const struct segment_command_64 *)cmd;
        if (strcmp(segment->segname, SEG_DATA) != 0) continue;
        const struct section_64 *section = (const struct section_64 *)(segment + 1);
        for (unsigned j = 0; j < segment->nsects; j++, section++) {
            uint32_t type = section->flags & SECTION_TYPE;
            if (type != S_LAZY_SYMBOL_POINTERS && type != S_NON_LAZY_SYMBOL_POINTERS) continue;
            void **pointers = (void **)(slide + section->addr);
            for (unsigned k = 0; k < section->size / sizeof(void *); k++) {
                uint32_t index = indirect[section->reserved1 + k];
                if (index & (INDIRECT_SYMBOL_ABS | INDIRECT_SYMBOL_LOCAL)) continue;
                if (index >= symtab->nsyms) continue;
                if (strcmp(strings + symbols[index].n_un.n_strx, "_xpc_dictionary_get_int64") != 0) continue;
                make_writable(&pointers[k]);
                pointers[k] = (void *)xpc_dictionary_get_int64_hook;
                syslog(LOG_NOTICE, "MIP: hooked xpc_dictionary_get_int64 in %s", image_info.dli_fname);
            }
        }
    }
}

static void __attribute__((constructor)) hook_lsd(void)
{
    /* Called for every image already loaded, then for each one loaded later. */
    _dyld_register_func_for_add_image(rebind_in_image);
}
