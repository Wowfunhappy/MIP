#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <alloca.h>
#include <mach/mach_vm.h>
#include <mach/mach.h> /* Mavericks port: mach/thread_state.h is 10.15+ */
#include <mach/vm_map.h>
#include <sys/sysctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <mach-o/nlist.h>
#include <libkern/OSByteOrder.h>
#include <injector/payloads/injected.h>
#include "inject.h"

#ifndef __x86_64__
typedef struct {
    uint64_t    __rax;
    uint64_t    __rbx;
    uint64_t    __rcx;
    uint64_t    __rdx;
    uint64_t    __rdi;
    uint64_t    __rsi;
    uint64_t    __rbp;
    uint64_t    __rsp;
    uint64_t    __r8;
    uint64_t    __r9;
    uint64_t    __r10;
    uint64_t    __r11;
    uint64_t    __r12;
    uint64_t    __r13;
    uint64_t    __r14;
    uint64_t    __r15;
    uint64_t    __rip;
    uint64_t    __rflags;
    uint64_t    __cs;
    uint64_t    __fs;
    uint64_t    __gs;
    uint64_t    __rosetta_offset;
} x86_thread_state64_t;
#endif

typedef struct {
    uint64_t rax;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rbx;
    uint64_t rsp;
    uint64_t rbp;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t flags;
} rosetta_state_t;


kern_return_t thread_get_state_x86_64(mach_port_t task, mach_port_t thread, x86_thread_state64_t *state)
{
#ifdef __x86_64__
    mach_msg_type_number_t size = x86_THREAD_STATE64_COUNT;
    return thread_get_state(thread, x86_THREAD_STATE64, (thread_state_t)state, &size);
#else
    arm_thread_state64_t arm_state;
    mach_msg_type_number_t size = ARM_THREAD_STATE64_COUNT;
    kern_return_t ret = thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t) &arm_state, &size);
    if (ret) return ret;
    
    /* Verify a "safe" injection state: the highest bit of X18 is set if we're
       outside of JIT code, then we know the registers stored in the Rosetta
       State buffer are up to date. Also, X28 *should* have the value of RIP
       during most instructions, so make sure it points to `retq` or a common
       libsystem_kernel return site. */
    if (!(arm_state.__x[18] & (1ULL << 63))) return -1;
    uint8_t opcodes[11];
    mach_vm_size_t read_size = sizeof(opcodes);
    ret = mach_vm_read_overwrite(task, arm_state.__x[28], read_size, (mach_vm_address_t)&opcodes, &read_size);
    if (ret) return ret;
    if (opcodes[0] != 0xc3) {
        /* Common return site pattern:
               73 08                   jae    .ret
               48 89 c7                mov    rdi,rax
               e9 xx xx xx xx          jmp    cerror_nocancel
           .ret
               c3                      ret
         */
        static const uint8_t return_site[] ={
            0x73, 0x08, 0x48, 0x89, 0xc7, 0xe9, 0, 0, 0, 0, 0xc3
        };
        opcodes[6] = opcodes[7] = opcodes[8] = opcodes[9] = 0;
        if (memcmp(opcodes, return_site, sizeof(return_site)) != 0) {
            return -2;
        }
    }
    
    rosetta_state_t rosetta_state;
    read_size = sizeof(rosetta_state);
    
    if (__builtin_available(macOS 13.0, *)) {
        state->__rosetta_offset = 16; // Only tested on macOS 15
    }
    else {
        state->__rosetta_offset = 64; // Only tested on macOS 12, known to not work on 13 & 14
    }
    
    ret = mach_vm_read_overwrite(task, (arm_state.__x[18] & ~(1ULL << 63)) + state->__rosetta_offset, read_size, (mach_vm_address_t) &rosetta_state, &read_size);
    
    if (ret) return ret;
    
    state->__rax = rosetta_state.rax;
    state->__rcx = rosetta_state.rcx;
    state->__rdx = rosetta_state.rdx;
    state->__rbx = rosetta_state.rbx;
    state->__rsp = rosetta_state.rsp;
    state->__rbp = rosetta_state.rbp;
    state->__rsi = rosetta_state.rsi;
    state->__rdi = rosetta_state.rdi;
    state->__r8  = rosetta_state.r8;
    state->__r9  = rosetta_state.r9;
    state->__r10 = rosetta_state.r10;
    state->__r11 = rosetta_state.r11;
    state->__r12 = rosetta_state.r12;
    state->__r13 = rosetta_state.r13;
    state->__r14 = rosetta_state.r14;
    state->__r15 = rosetta_state.r15;
    state->__rip = arm_state.__x[28];
    
    
    // Todo: convert flags from ARM to Intel, find the segment registers
        
    return 0;
#endif
}

kern_return_t thread_set_state_x86_64(mach_port_t task, mach_port_t thread, const x86_thread_state64_t *state)
{
#ifdef __x86_64__
    return thread_set_state(thread, x86_THREAD_STATE64, (thread_state_t)state, x86_THREAD_STATE64_COUNT);
#else
    arm_thread_state64_t arm_state;
    mach_msg_type_number_t size = ARM_THREAD_STATE64_COUNT;
    kern_return_t ret = thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t) &arm_state, &size);
    if (ret) return ret;
    if (!(arm_state.__x[18] & (1ULL << 63))) return -1;
    rosetta_state_t rosetta_state;
    mach_vm_size_t read_size = sizeof(rosetta_state);
    ret = mach_vm_read_overwrite(task, (arm_state.__x[18] & ~(1ULL << 63)) + state->__rosetta_offset, read_size, (mach_vm_address_t) &rosetta_state, &read_size);
    
    if (ret) return ret;
    
    rosetta_state.rax = state->__rax;
    rosetta_state.rcx = state->__rcx;
    rosetta_state.rdx = state->__rdx;
    rosetta_state.rbx = state->__rbx;
    rosetta_state.rsp = state->__rsp;
    rosetta_state.rbp = state->__rbp;
    rosetta_state.rsi = state->__rsi;
    rosetta_state.rdi = state->__rdi;
    rosetta_state.r8  = state->__r8;
    rosetta_state.r9  = state->__r9;
    rosetta_state.r10 = state->__r10;
    rosetta_state.r11 = state->__r11;
    rosetta_state.r12 = state->__r12;
    rosetta_state.r13 = state->__r13;
    rosetta_state.r14 = state->__r14;
    rosetta_state.r15 = state->__r15;
    
    return mach_vm_write(task, (arm_state.__x[18] & ~(1ULL << 63)) + state->__rosetta_offset, (vm_offset_t)&rosetta_state, sizeof(rosetta_state));
#endif
}

kern_return_t inject_call_to_thread_x86_64(mach_port_t task, mach_port_t thread, uint64_t function, uint64_t ret_addr)
{
    x86_thread_state64_t state;
    kern_return_t ret = KERN_SUCCESS;
    
    ret = thread_suspend(thread);
    if (ret) goto exit;
    
    ret = thread_get_state_x86_64(task, thread, &state);
    if (ret) goto exit;
    
    if (state.__rsp & 7) {
        ret = KERN_INVALID_ADDRESS;
        goto exit;
    }
    
#ifdef __x86_64__
    /* Push PC */
    state.__rsp -= sizeof(state.__rip);
    mach_vm_write(task, state.__rsp, (vm_offset_t)&state.__rip, sizeof(state.__rip));
    
    /* x86-64 stack % 16 must be 8 bytes after a call instruction */
    if ((state.__rsp & 0xF) == 0) {
        /* Push a nop function as a return address, for alignment */
        state.__rsp -= sizeof(state.__rip);
        mach_vm_write(task, state.__rsp, (vm_offset_t)&ret_addr, sizeof(ret_addr));
    }
    
    /* Update PC */
    state.__rip = function;
#else
    /* Push a NOP function as a return address for alignment, followed by our call */
    state.__rsp -= sizeof(state.__rip) * 2;
    uint64_t stack[2] = {
        ret_addr,
        function,
    };
    mach_vm_write(task, state.__rsp, (vm_offset_t)&stack, sizeof(stack));
#endif
    
    ret = thread_set_state_x86_64(task, thread, &state);
    if (ret) goto exit;
    
exit:
    thread_resume(thread);
    return ret;
}

#ifndef __x86_64__
kern_return_t inject_call_to_thread_arm(mach_port_t task, mach_port_t thread, uint64_t function, uint64_t ret_addr)
{
    arm_thread_state64_t state;
    mach_msg_type_number_t size = ARM_THREAD_STATE64_COUNT;
    kern_return_t ret = KERN_SUCCESS;
    
    ret = thread_suspend(thread);
    if (ret) goto exit;
    
    ret = thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t) &state, &size);
    if (ret) goto exit;
    
    thread_convert_thread_state(thread, THREAD_CONVERT_THREAD_STATE_TO_SELF, ARM_THREAD_STATE64, (thread_state_t)&state, size, (thread_state_t)&state, &size);

    /* Save PC to FP */
    __darwin_arm_thread_state64_set_fp(state, (void *)((uint64_t)state.__opaque_pc & 0xFFFFFFFFFFF));
    
    /* Update PC */
    __darwin_arm_thread_state64_set_pc_fptr(state, ptrauth_sign_unauthenticated((void *)function, ptrauth_key_function_pointer, 0));
    
    thread_convert_thread_state(thread, THREAD_CONVERT_THREAD_STATE_FROM_SELF, ARM_THREAD_STATE64, (thread_state_t)&state, size, (thread_state_t)&state, &size);
    ret = thread_set_state(thread, ARM_THREAD_STATE64, (thread_state_t) &state, size);
    if (ret) goto exit;
    
exit:
    thread_resume(thread);
    return ret;
}
#endif

#ifdef __x86_64__
kern_return_t inject_call_to_thread_i386(mach_port_t task, mach_port_t thread, uint32_t function, uint32_t ret_addr)
{
    x86_thread_state32_t state;
    mach_msg_type_number_t size = x86_THREAD_STATE32_COUNT;
    kern_return_t ret = KERN_SUCCESS;

    ret = thread_suspend(thread);
    if (ret) goto exit;

    ret = thread_get_state(thread, x86_THREAD_STATE32, (thread_state_t) &state, &size);
    if (ret) goto exit;

    if (state.__esp & 3) {
        ret = KERN_INVALID_ADDRESS;
        goto exit;
    }

    /* Push PC */
    state.__esp -= sizeof(state.__eip);
    mach_vm_write(task, state.__esp, (vm_offset_t)&state.__eip, sizeof(state.__eip));

    /* x86-32 stack % 16 must be 0xC bytes after a call instruction */
    while ((state.__esp & 0xF) != 0xC) {
        /* Push a nop function as a return address, for alignment */
        state.__esp -= sizeof(state.__eip);
        mach_vm_write(task, state.__esp, (vm_offset_t)&ret_addr, sizeof(ret_addr));
    }

    /* Update PC */
    state.__eip = function;
    ret = thread_set_state(thread, x86_THREAD_STATE32, (thread_state_t) &state, size);
    if (ret) goto exit;

exit:
    thread_resume(thread);
    return ret;
}
#endif

kern_return_t get_thread_port_for_task(mach_port_t task, mach_port_t *thread)
{
    thread_array_t thread_list = NULL;
    mach_msg_type_number_t thread_list_count = 0;
    kern_return_t ret = task_threads(task, &thread_list, &thread_list_count);
    if (ret) return ret;
    /* The first thread returned is the first thread created in the task, which is the main thread.
       This was verified in the kernel sources. */
    *thread = thread_list[0];
    for (unsigned i = 1; i < thread_list_count; i++) {
        mach_port_destroy(mach_task_self(), thread_list[i]);
    }
    vm_deallocate(mach_task_self(), (vm_address_t) thread_list, thread_list_count * sizeof(thread_list[0]));
    return KERN_SUCCESS;
}

static bool is_arm(mach_port_t task)
{
#ifdef __x86_64__
    return false;
#else
    pid_t pid;
    pid_for_task(task, &pid);
    int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
    
    struct kinfo_proc proc;
    size_t buf_size = sizeof(proc);

    if (sysctl(mib, sizeof(mib) / sizeof(mib[0]), &proc, &buf_size, NULL, 0) < 0) {
        perror("Failure calling sysctl");
        return false;
    }
    
    return !(proc.kp_proc.p_flag & P_TRANSLATED);
#endif
}

kern_return_t inject_stub_to_task(mach_port_t task, mach_vm_address_t *addr, mach_vm_address_t *ret_addr,
                                  const char *argument, bool is_arm, bool *is_32_bit)
{
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    struct task_dyld_info info;
    kern_return_t ret = task_info(task, TASK_DYLD_INFO, (task_info_t) &info, &count);
    if (ret) return ret;
    *is_32_bit = info.all_image_info_format == TASK_DYLD_ALL_IMAGE_INFO_32;
    
    uint8_t *code = NULL;
    size_t code_size = 0;
#ifdef __x86_64__
    if (*is_32_bit) {
        code_size = &injected_i386_end - &injected_i386_start + 1; // +1 for the injected ret instruction, for stack alignment
        code = alloca(code_size);
        memcpy(code, &injected_i386_start, code_size);
        code[code_size - 1] = 0xc3; // ret;
        
        uint32_t dyld_magic = DYLD_MAGIC_32;
        *(uint32_t*) memmem(code, code_size, &dyld_magic, sizeof(dyld_magic)) = (uint32_t)info.all_image_info_addr;
        
        strcpy(memmem(code, code_size, ARGUMENT_MAGIC_STR, sizeof(ARGUMENT_MAGIC_STR)), argument);
    }
    else
#endif
#ifndef __x86_64__
    if (is_arm) {
        code_size = &injected_arm_end - &injected_arm_start;
        code = alloca(code_size);
        memcpy(code, &injected_arm_start, code_size);
        
        uint64_t dyld_magic = DYLD_MAGIC_64;
        *(uint64_t*) memmem(code, code_size, &dyld_magic, sizeof(dyld_magic)) = info.all_image_info_addr;
        
        strcpy(memmem(code, code_size, ARGUMENT_MAGIC_STR, sizeof(ARGUMENT_MAGIC_STR)), argument);
    }
    else
#endif
    {
        code_size = &injected_x86_64_end - &injected_x86_64_start + 1; // +1 for the injected ret instruction, for stack alignment
        code = alloca(code_size);
        memcpy(code, &injected_x86_64_start, code_size - 1);
        code[code_size - 1] = 0xc3; // ret;
        
        uint64_t dyld_magic = DYLD_MAGIC_64;
        *(uint64_t*) memmem(code, code_size, &dyld_magic, sizeof(dyld_magic)) = info.all_image_info_addr;
        
        strcpy(memmem(code, code_size, ARGUMENT_MAGIC_STR, sizeof(ARGUMENT_MAGIC_STR)), argument);
    }
    
    ret = mach_vm_allocate(task, addr, code_size, VM_FLAGS_ANYWHERE);
    if (ret) return ret;
    
    ret = mach_vm_write(task, *addr, (vm_offset_t) code, (mach_msg_type_number_t) code_size);
    if (ret) return ret;
    
    vm_prot_t prot = VM_PROT_READ | VM_PROT_EXECUTE;
#ifndef __x86_64__
    if (!is_arm) {
        prot |= VM_PROT_WRITE;
    }
#endif
    
    ret = vm_protect(task, *addr, code_size, FALSE, prot);
    if (ret) return ret;
    
    *ret_addr = *addr + code_size - 1;
    
    return KERN_SUCCESS;
}

kern_return_t inject_to_task(mach_port_t task, const char *argument)
{
    mach_port_t thread;
    kern_return_t ret = KERN_SUCCESS;
    
    if ((ret = get_thread_port_for_task(task, &thread))) {
        return ret;
    }
    
    ret = inject_to_task_thread(task, thread, argument);
    mach_port_destroy(mach_task_self(), thread);
    return ret;
}

/* Mavericks port: inject_to_task, with the main thread's port given by the
   caller (and left to it): ports for the same thread share a name, so
   destroying one would take the caller's away too. */
kern_return_t inject_to_task_thread(mach_port_t task, mach_port_t thread, const char *argument)
{
    kern_return_t ret = KERN_SUCCESS;
    
    if (strlen(argument) + 1 > ARGUMENT_MAX_LENGTH) {
        return KERN_INVALID_ARGUMENT;
    }
    
    mach_vm_address_t code_addr = 0;
    mach_vm_address_t ret_addr = 0;
    bool is_32_bit = false;
    bool arm = is_arm(task);
    
    if ((ret = inject_stub_to_task(task, &code_addr, &ret_addr, argument, arm, &is_32_bit))) {
        return ret;
    }
    
#ifndef __x86_64__
    if (arm) {
        ret = inject_call_to_thread_arm(task, thread, code_addr, ret_addr);
    }
#else
    if (is_32_bit) {
        ret = inject_call_to_thread_i386(task, thread, (uint32_t)code_addr, (uint32_t)ret_addr);
    }
#endif
    else {
        ret = inject_call_to_thread_x86_64(task, thread, code_addr, ret_addr);
    }
    
    return ret;
}

/* Mavericks port: whether an image with this exact path is in the task's dyld
   image list (as dlopen records it: the path it was given). */
bool task_has_image(mach_port_t task, const char *path)
{
    struct task_dyld_info info;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    if (task_info(task, TASK_DYLD_INFO, (task_info_t)&info, &count)) return false;
    bool is_32_bit = info.all_image_info_format == TASK_DYLD_ALL_IMAGE_INFO_32;

    /* dyld_all_image_infos starts { uint32_t version; uint32_t infoArrayCount; infoArray pointer }. */
    uint8_t header[16];
    mach_vm_size_t size = 0;
    if (mach_vm_read_overwrite(task, info.all_image_info_addr, sizeof(header), (mach_vm_address_t)header, &size)) return false;
    uint32_t image_count = *(uint32_t *)(header + 4);
    uint64_t images = is_32_bit ? *(uint32_t *)(header + 8) : *(uint64_t *)(header + 8);
    if (!images) return false;   /* dyld is changing the list */

    /* Each dyld_image_info: { load address, path, modification date }, pointer-sized. */
    size_t pointer_size = is_32_bit ? 4 : 8;
    size_t length = strlen(path) + 1;
    char name[length];
    for (uint32_t i = 0; i < image_count; i++) {
        uint64_t name_address = 0;
        if (mach_vm_read_overwrite(task, images + i * 3 * pointer_size + pointer_size, pointer_size,
                                   (mach_vm_address_t)&name_address, &size)) return false;
        if (!name_address) continue;
        if (mach_vm_read_overwrite(task, name_address, length, (mach_vm_address_t)name, &size)) continue;
        if (memcmp(name, path, length) == 0) return true;
    }
    return false;
}

/* Mavericks port: whether a suspended thread is blocked in mach_msg_trap, as
   an application's main thread is while idle in its run loop, so that a call
   injected there runs where no lock of the application's is held. (In a
   blocked trap the saved rax/eax still holds the trap number.) */
bool thread_is_in_mach_msg(mach_port_t thread)
{
    x86_thread_state_t state;
    mach_msg_type_number_t count = x86_THREAD_STATE_COUNT;
    if (thread_get_state(thread, x86_THREAD_STATE, (thread_state_t)&state, &count)) return false;
    if (state.tsh.flavor == x86_THREAD_STATE64) return state.uts.ts64.__rax == 0x100001f;  /* SYSCALL_CLASS_MACH | 31 */
    return state.uts.ts32.__eax == (uint32_t)-31;                                            /* i386 mach traps: -number */
}

/* Mavericks port: setuid/setgid processes (P_SUGID: what issetugid() reports
   in the process itself) are left alone, as dyld leaves them alone with
   DYLD_INSERT_LIBRARIES. Bundles have no business running with privileges the
   user doesn't have, and AppKit refuses to run in such processes: the first
   use of NSApplication or NSWindow logs "...is running setugid(), which is
   not allowed." and exits. A process like VMware Fusion's vmware-vmx (setuid
   root) links AppKit without using it, and a bundle loaded into it - any
   that touches NSWindow as it loads - kills it. The loader checks too. */
bool process_is_setugid(pid_t pid)
{
    struct kinfo_proc info;
    size_t size = sizeof(info);
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, pid };
    if (sysctl(mib, 4, &info, &size, NULL, 0) != 0 || size == 0) return true;  /* unknown: leave it alone */
    return (info.kp_proc.p_flag & P_SUGID) != 0;
}

/* Mavericks port: the thread that is checking in.

   launchservicesd injects when a process checks in (_LSApplicationCheckIn,
   command 500), before replying, so that the injected call runs at a known
   point: in the thread blocked waiting for that reply. An application checks
   in from its main thread, but not every process does - a view service (such
   as AppKit's save panel service) checks in from a background queue while its
   main thread idles in a run loop, and a call injected into the main thread
   there runs at whatever point it next wakes. So the call goes to the thread
   that is actually checking in: the one blocked in the kernel (waiting for
   the reply) with _LSApplicationCheckIn among its callers (found by walking its frame
   pointers). If there is none, nothing is injected.

   _LSApplicationCheckIn's extent (from its symbol to the next function start,
   LC_FUNCTION_STARTS) is read once per architecture from LaunchServices on
   disk, as offsets; each process's copy is found in its dyld image list. */

#define LAUNCHSERVICES_PATH "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/LaunchServices"
#define LAUNCHSERVICES_SUFFIX "/LaunchServices.framework/Versions/A/LaunchServices"

typedef struct { bool done, valid; uint64_t start, end; } check_in_range_t;

static uint64_t read_uleb128(const uint8_t **p, const uint8_t *end)
{
    uint64_t value = 0; int shift = 0;
    while (*p < end) {
        uint8_t byte = *(*p)++;
        value |= (uint64_t)(byte & 0x7f) << shift;
        shift += 7;
        if (!(byte & 0x80)) break;
    }
    return value;
}

/* Offsets of _LSApplicationCheckIn's first byte and of the next function's,
   from LaunchServices' header, in its slice for this CPU type. */
static bool check_in_range_from_file(cpu_type_t cpu, uint64_t *start, uint64_t *end)
{
    bool found = false;
    int fd = open(LAUNCHSERVICES_PATH, O_RDONLY);
    if (fd < 0) return false;
    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return false; }
    const uint8_t *file = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (file == MAP_FAILED) return false;
    size_t size = (size_t)st.st_size;

    /* The slice for this CPU type. */
    const uint8_t *slice = NULL;
    size_t slice_size = 0;
    if (size >= sizeof(struct fat_header) && OSSwapBigToHostInt32(((const struct fat_header *)file)->magic) == FAT_MAGIC) {
        uint32_t count = OSSwapBigToHostInt32(((const struct fat_header *)file)->nfat_arch);
        const struct fat_arch *arch = (const struct fat_arch *)(file + sizeof(struct fat_header));
        for (uint32_t i = 0; i < count && (const uint8_t *)(arch + i + 1) <= file + size; i++) {
            if ((cpu_type_t)OSSwapBigToHostInt32(arch[i].cputype) != cpu) continue;
            uint32_t offset = OSSwapBigToHostInt32(arch[i].offset), length = OSSwapBigToHostInt32(arch[i].size);
            if ((uint64_t)offset + length <= size) { slice = file + offset; slice_size = length; }
        }
    }
    else if (size >= sizeof(struct mach_header) && ((const struct mach_header *)file)->cputype == cpu) {
        slice = file; slice_size = size;
    }
    if (!slice || slice_size < sizeof(struct mach_header_64)) goto done;

    const struct mach_header *header = (const struct mach_header *)slice;
    bool is_64 = header->magic == MH_MAGIC_64;
    if (!is_64 && header->magic != MH_MAGIC) goto done;
    const uint8_t *command = slice + (is_64 ? sizeof(struct mach_header_64) : sizeof(struct mach_header));
    uint64_t text_address = 0, text_size = 0;
    const struct symtab_command *symtab = NULL;
    const struct linkedit_data_command *function_starts = NULL;
    bool have_text = false;
    for (uint32_t i = 0; i < header->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)command;
        if (command + sizeof(*lc) > slice + slice_size || lc->cmdsize < sizeof(*lc)) goto done;
        if (lc->cmd == LC_SEGMENT_64 && is_64 && strncmp(((const struct segment_command_64 *)lc)->segname, SEG_TEXT, 16) == 0) {
            text_address = ((const struct segment_command_64 *)lc)->vmaddr; text_size = ((const struct segment_command_64 *)lc)->vmsize; have_text = true;
        }
        else if (lc->cmd == LC_SEGMENT && !is_64 && strncmp(((const struct segment_command *)lc)->segname, SEG_TEXT, 16) == 0) {
            text_address = ((const struct segment_command *)lc)->vmaddr; text_size = ((const struct segment_command *)lc)->vmsize; have_text = true;
        }
        else if (lc->cmd == LC_SYMTAB) symtab = (const struct symtab_command *)lc;
        else if (lc->cmd == LC_FUNCTION_STARTS) function_starts = (const struct linkedit_data_command *)lc;
        command += lc->cmdsize;
    }
    if (!have_text || !symtab || !function_starts) goto done;
    if ((uint64_t)symtab->stroff + symtab->strsize > slice_size
        || (uint64_t)symtab->symoff + (uint64_t)symtab->nsyms * (is_64 ? sizeof(struct nlist_64) : sizeof(struct nlist)) > slice_size
        || (uint64_t)function_starts->dataoff + function_starts->datasize > slice_size) goto done;

    /* The symbol. */
    const char *strings = (const char *)slice + symtab->stroff;
    uint64_t symbol = 0;
    for (uint32_t i = 0; i < symtab->nsyms; i++) {
        uint32_t strx; uint8_t type; uint64_t value;
        if (is_64) { const struct nlist_64 *n = (const struct nlist_64 *)(slice + symtab->symoff) + i; strx = n->n_un.n_strx; type = n->n_type; value = n->n_value; }
        else { const struct nlist *n = (const struct nlist *)(slice + symtab->symoff) + i; strx = n->n_un.n_strx; type = n->n_type; value = n->n_value; }
        if ((type & N_TYPE) != N_SECT || strx >= symtab->strsize) continue;
        if (strcmp(strings + strx, "__LSApplicationCheckIn") == 0) { symbol = value; break; }
    }
    if (!symbol) goto done;

    /* The function start after it (or the end of __TEXT). */
    const uint8_t *p = slice + function_starts->dataoff, *p_end = p + function_starts->datasize;
    uint64_t address = text_address;
    bool at_symbol = false;
    uint64_t next = text_address + text_size;
    while (p < p_end) {
        uint64_t delta = read_uleb128(&p, p_end);
        if (!delta) break;
        address += delta;
        if (at_symbol) { next = address; break; }
        if (address == symbol) at_symbol = true;
    }
    if (!at_symbol) goto done;
    *start = symbol - text_address;
    *end = next - text_address;
    found = true;

done:
    munmap((void *)file, size);
    return found;
}

/* Where the task's LaunchServices is loaded. */
static bool task_image_address(mach_port_t task, const char *suffix, bool *is_32_bit, uint64_t *address)
{
    struct task_dyld_info info;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    if (task_info(task, TASK_DYLD_INFO, (task_info_t)&info, &count)) return false;
    *is_32_bit = info.all_image_info_format == TASK_DYLD_ALL_IMAGE_INFO_32;
    uint8_t header[16];
    mach_vm_size_t size = 0;
    if (mach_vm_read_overwrite(task, info.all_image_info_addr, sizeof(header), (mach_vm_address_t)header, &size)) return false;
    uint32_t image_count = *(uint32_t *)(header + 4);
    uint64_t images = *is_32_bit ? *(uint32_t *)(header + 8) : *(uint64_t *)(header + 8);
    if (!images) return false;
    size_t pointer_size = *is_32_bit ? 4 : 8, suffix_length = strlen(suffix);
    for (uint32_t i = 0; i < image_count; i++) {
        uint64_t entry[2] = { 0, 0 };   /* load address, path */
        uint8_t raw[16];
        if (mach_vm_read_overwrite(task, images + i * 3 * pointer_size, 2 * pointer_size, (mach_vm_address_t)raw, &size)) return false;
        if (*is_32_bit) { entry[0] = *(uint32_t *)raw; entry[1] = *(uint32_t *)(raw + 4); }
        else { entry[0] = *(uint64_t *)raw; entry[1] = *(uint64_t *)(raw + 8); }
        if (!entry[1]) continue;
        /* The path's last bytes: read its start, find its end. */
        char path[1025];
        mach_vm_size_t got = 0;
        /* (A read running past the end of the path's mapping fails: then a shorter one.) */
        if (mach_vm_read_overwrite(task, entry[1], 1024, (mach_vm_address_t)path, &got)
            && mach_vm_read_overwrite(task, entry[1], 256, (mach_vm_address_t)path, &got)) continue;
        path[got] = 0;
        size_t length = strnlen(path, sizeof(path));
        if (length >= suffix_length && strcmp(path + length - suffix_length, suffix) == 0) { *address = entry[0]; return true; }
    }
    return false;
}

/* Whether one of the thread's callers (by its frame pointers) is in [start, end). */
static bool thread_has_caller_in(mach_port_t task, mach_port_t thread, uint64_t start, uint64_t end)
{
    x86_thread_state_t state;
    mach_msg_type_number_t count = x86_THREAD_STATE_COUNT;
    if (thread_get_state(thread, x86_THREAD_STATE, (thread_state_t)&state, &count)) return false;
    bool is_64 = state.tsh.flavor == x86_THREAD_STATE64;
    uint64_t frame = is_64 ? state.uts.ts64.__rbp : state.uts.ts32.__ebp;
    size_t pointer_size = is_64 ? 8 : 4;
    for (int depth = 0; depth < 64 && frame && !(frame & (pointer_size - 1)); depth++) {
        uint8_t raw[16];
        mach_vm_size_t size = 0;
        if (mach_vm_read_overwrite(task, frame, 2 * pointer_size, (mach_vm_address_t)raw, &size) || size != 2 * pointer_size) return false;
        uint64_t next = is_64 ? *(uint64_t *)raw : *(uint32_t *)raw;
        uint64_t return_address = is_64 ? *(uint64_t *)(raw + 8) : *(uint32_t *)(raw + 4);
        if (return_address > start && return_address <= end) return true;   /* a return address follows its call */
        if (next <= frame) return false;   /* frames go up the stack */
        frame = next;
    }
    return false;
}

/* Whether the thread is blocked in the kernel - as the one checking in is,
   waiting for launchservicesd's reply (in semaphore_wait_trap, under
   xpc_connection_send_message_with_reply_sync). */
static bool thread_is_blocked(mach_port_t thread)
{
    thread_basic_info_data_t info;
    mach_msg_type_number_t count = THREAD_BASIC_INFO_COUNT;
    if (thread_info(thread, THREAD_BASIC_INFO, (thread_info_t)&info, &count)) return false;
    return info.run_state == TH_STATE_WAITING;
}

static pthread_mutex_t check_in_ranges_lock = PTHREAD_MUTEX_INITIALIZER;
static check_in_range_t check_in_ranges[2];    /* [0] x86_64, [1] i386 */

bool find_check_in_thread(mach_port_t task, mach_port_t *thread_out, const char **why)
{
    bool is_32_bit = false;
    uint64_t launchservices = 0;
    if (!task_image_address(task, LAUNCHSERVICES_SUFFIX, &is_32_bit, &launchservices)) {
        *why = "LaunchServices not found in its images";
        return false;
    }

    pthread_mutex_lock(&check_in_ranges_lock);
    check_in_range_t *range = &check_in_ranges[is_32_bit ? 1 : 0];
    if (!range->done) {
        range->valid = check_in_range_from_file(is_32_bit ? CPU_TYPE_I386 : CPU_TYPE_X86_64, &range->start, &range->end);
        range->done = true;
    }
    check_in_range_t r = *range;
    pthread_mutex_unlock(&check_in_ranges_lock);
    if (!r.valid) {
        *why = "_LSApplicationCheckIn not found in LaunchServices";
        return false;
    }

    thread_array_t threads = NULL;
    mach_msg_type_number_t thread_count = 0;
    if (task_threads(task, &threads, &thread_count)) {
        *why = "its threads could not be listed";
        return false;
    }
    /* The main thread (the first) first: an application's. */
    mach_port_t found = MACH_PORT_NULL;
    for (mach_msg_type_number_t i = 0; i < thread_count; i++) {
        if (found == MACH_PORT_NULL && thread_is_blocked(threads[i])
            && thread_has_caller_in(task, threads[i], launchservices + r.start, launchservices + r.end)) {
            found = threads[i];
            continue;
        }
        mach_port_deallocate(mach_task_self(), threads[i]);
    }
    vm_deallocate(mach_task_self(), (vm_address_t)threads, thread_count * sizeof(threads[0]));
    if (found == MACH_PORT_NULL) {
        *why = "no thread is waiting in _LSApplicationCheckIn";
        return false;
    }
    *thread_out = found;
    return true;
}
