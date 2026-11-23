/* Mavericks port: in-process replacement for injectd_client.

   Upstream routes every injection through `injectd`, a root daemon with the
   com.apple.private.thread-set-state entitlement, because launchservicesd on
   newer systems is not allowed to take other processes' task ports. On 10.9
   launchservicesd runs as root without a sandbox, and `inject` is only ever
   run as root, so both can call task_for_pid themselves. */

#include <mach/mach.h>
#include <stdbool.h>
#include <syslog.h>
#include "injectd_client/injectd_client.h"
#include "inject/inject.h"


const char *inject_to_pid(pid_t pid, const char *dylib, bool interrupt_syscalls)
{
    mach_port_t task = MACH_PORT_NULL;
    kern_return_t ret = task_for_pid(mach_task_self(), pid, &task);
    if (ret) {
        syslog(LOG_ERR, "MIP: task_for_pid(%d) failed: %d", pid, ret);
        return "Failed to obtain task for PID.";
    }

    ret = inject_to_task(task, dylib);
    if (ret) {
        syslog(LOG_ERR, "MIP: injecting %s into %d failed: %d", dylib, pid, ret);
        mach_port_deallocate(mach_task_self(), task);
        return "Injection failed, check Console for details.";
    }

    const char *result = NULL;
    if (interrupt_syscalls) {
        /* This interrupts blocking system calls to ensure execution. */
        mach_port_t thread;
        ret = get_thread_port_for_task(task, &thread);
        if (!ret) {
            ret = thread_abort(thread);
            mach_port_deallocate(mach_task_self(), thread);
        }
        if (ret) {
            result = "Injection succeeded, but the injected library will only run after the main thread wakes up.";
        }
    }

    mach_port_deallocate(mach_task_self(), task);
    return result;
}
