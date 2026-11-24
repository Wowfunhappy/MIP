#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <mach/mach.h>
#include <errno.h>
#include <sys/types.h>
#include <signal.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>
#include <syslog.h>
#include <libgen.h>
#include <sys/syslimits.h>
#include <CoreFoundation/CoreFoundation.h>
#include "injectd_client/injectd_client.h"
#include "inject/inject.h"

/* Mavericks port: in -w mode (how local.lsdinjector runs it at boot), the
   injection is verified, and with -c, applications that checked in with
   launchservicesd before it was hooked are caught up.

   launchservicesd starts on demand, when loginwindow first needs it, and is
   only hooked some seconds later (-w4: upstream's delay, as injecting sooner
   can fail on newer systems). An application that checks in meanwhile - with
   automatic login, the session's Finder, Dock and SystemUIServer can - gets
   nothing injected, and stays that way until it is relaunched. So once the
   hook is in place (lsdinjector.dylib is in launchservicesd's image list; any
   check-in from then on is caught by it), the dylib given with -c (MIP's
   loader) is injected into every application LaunchServices already lists
   that doesn't have it.

   Unlike at check-in, such an application is not waiting at a known point, so
   the loader is only injected into one that has finished launching (it has
   told LaunchServices it is ready) and whose main thread is idle, blocked in
   mach_msg (its run loop); one still launching is waited for. The loader
   handles loading after launch, as for a manual injection: SIMBL plugins load
   at once.

   Only on a fresh launchservicesd (at boot): when MIP is installed into a
   running session, the applications already running are left alone, as the
   installer asks for a logout instead. */

/* LaunchServices (private, 10.9) */
typedef int LSSessionID;
#define kLSDefaultSessionID ((LSSessionID)-2)
extern CFArrayRef _LSCopyRunningApplicationArray(LSSessionID sessionID);
extern CFTypeRef _LSCopyApplicationInformationItem(LSSessionID sessionID, CFTypeRef asn, CFStringRef key);
extern const CFStringRef _kLSPIDKey;
extern const CFStringRef _kLSApplicationHasSignalledItIsReadyKey;

#define CATCH_UP_SECONDS 30
#ifndef FRESH_SECONDS
#define FRESH_SECONDS 60
#endif

static time_t process_start_time(pid_t pid)
{
    struct kinfo_proc info;
    size_t size = sizeof(info);
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, pid };
    if (sysctl(mib, 4, &info, &size, NULL, 0) != 0 || size == 0) return 0;
    return info.kp_proc.p_starttime.tv_sec;
}

static bool pid_has_image(pid_t pid, const char *path)
{
    mach_port_t task = MACH_PORT_NULL;
    if (task_for_pid(mach_task_self(), pid, &task)) return false;
    bool loaded = task_has_image(task, path);
    mach_port_deallocate(mach_task_self(), task);
    return loaded;
}

/* Injects into pid and waits up to two seconds for the dylib to be loaded,
   retrying a few times (upstream saw injections into a just-started
   launchservicesd silently fail). */
static const char *inject_verified(pid_t pid, const char *dylib)
{
    const char *error = "The library was not loaded.";
    for (int attempt = 0; attempt < 5; attempt++) {
        if (attempt) {
            fprintf(stderr, "%s was not loaded into %d; retrying\n", dylib, pid);
            sleep(1);
        }
        const char *result = inject_to_pid(pid, dylib, true);
        if (result) error = result;
        for (int i = 0; i < 20; i++) {
            if (pid_has_image(pid, dylib)) return NULL;
            usleep(100000);
        }
    }
    return error;
}

typedef enum { CATCH_UP_DONE, CATCH_UP_WAIT } catch_up_state;

/* Injects dylib into pid if it is ready, idle, and doesn't have it yet. */
static catch_up_state catch_up_pid(pid_t pid, const char *dylib, bool ready)
{
    if (process_is_setugid(pid)) return CATCH_UP_DONE;
    mach_port_t task = MACH_PORT_NULL;
    if (task_for_pid(mach_task_self(), pid, &task)) return CATCH_UP_DONE;   /* gone */
    catch_up_state state = CATCH_UP_WAIT;
    if (task_has_image(task, dylib)) {
        state = CATCH_UP_DONE;
    }
    else if (ready) {
        mach_port_t thread = MACH_PORT_NULL;
        if (get_thread_port_for_task(task, &thread) == KERN_SUCCESS) {
            /* Suspended across the check and the injection, so it can't move on in between. */
            if (thread_suspend(thread) == KERN_SUCCESS) {
                if (thread_is_in_mach_msg(thread)) {
                    kern_return_t ret = inject_to_task_thread(task, thread, dylib);
                    if (ret == KERN_SUCCESS) {
                        thread_abort(thread);   /* wake it from mach_msg into the injected call; mach_msg resumes after */
                        syslog(LOG_NOTICE, "MIP: %d had checked in before launchservicesd was hooked; injected %s", pid, dylib);
                    }
                    else {
                        syslog(LOG_ERR, "MIP: injecting %s into %d failed: %d", dylib, pid, ret);
                    }
                    state = CATCH_UP_DONE;
                }
                thread_resume(thread);
            }
            mach_port_deallocate(mach_task_self(), thread);
        }
    }
    mach_port_deallocate(mach_task_self(), task);
    return state;
}

static void catch_up(const char *dylib, pid_t server)
{
    /* MIP's kill switch: <MIP root>/disabled, beside the loader. */
    char disabled[PATH_MAX];
    snprintf(disabled, sizeof(disabled), "%s/disabled", dirname((char *)strdup(dylib)));

    /* Each application is handled once: one injected into may not have run the
       injected call yet, and would still look idle. */
    pid_t done[1024];
    unsigned done_count = 0;

    time_t deadline = time(NULL) + CATCH_UP_SECONDS;
    do {
        bool pending = false;
        if (access(disabled, F_OK) == 0) return;
        CFArrayRef applications = _LSCopyRunningApplicationArray(kLSDefaultSessionID);
        if (!applications) return;
        for (CFIndex i = 0; i < CFArrayGetCount(applications); i++) {
            CFTypeRef asn = CFArrayGetValueAtIndex(applications, i);
            CFNumberRef number = _LSCopyApplicationInformationItem(kLSDefaultSessionID, asn, _kLSPIDKey);
            CFTypeRef ready = _LSCopyApplicationInformationItem(kLSDefaultSessionID, asn, _kLSApplicationHasSignalledItIsReadyKey);
            pid_t pid = 0;
            if (number && CFGetTypeID(number) == CFNumberGetTypeID()) CFNumberGetValue(number, kCFNumberIntType, &pid);
            bool handled = false;
            for (unsigned j = 0; j < done_count; j++) {
                if (done[j] == pid) handled = true;
            }
            if (pid > 0 && pid != server && pid != getpid() && !handled) {
                if (catch_up_pid(pid, dylib, ready == kCFBooleanTrue) == CATCH_UP_WAIT) pending = true;
                else if (done_count < sizeof(done) / sizeof(done[0])) done[done_count++] = pid;
            }
            if (number) CFRelease(number);
            if (ready) CFRelease(ready);
        }
        CFRelease(applications);
        if (!pending) return;
        usleep(200000);
    } while (time(NULL) < deadline);

    /* Still launching, or never idle: left alone, as before. */
    CFArrayRef applications = _LSCopyRunningApplicationArray(kLSDefaultSessionID);
    if (!applications) return;
    for (CFIndex i = 0; i < CFArrayGetCount(applications); i++) {
        CFNumberRef number = _LSCopyApplicationInformationItem(kLSDefaultSessionID, CFArrayGetValueAtIndex(applications, i), _kLSPIDKey);
        pid_t pid = 0;
        if (number && CFGetTypeID(number) == CFNumberGetTypeID()) CFNumberGetValue(number, kCFNumberIntType, &pid);
        if (number) CFRelease(number);
        bool handled = false;
        for (unsigned j = 0; j < done_count; j++) {
            if (done[j] == pid) handled = true;
        }
        if (pid > 0 && pid != server && !handled && !pid_has_image(pid, dylib) && !process_is_setugid(pid)) {
            syslog(LOG_NOTICE, "MIP: %d had checked in before launchservicesd was hooked, but never became ready and idle; %s was not injected", pid, dylib);
        }
    }
    CFRelease(applications);
}

int main(int argc, const char **argv)
{
    bool wait_for_process = false;
    unsigned delay = 0;
    const char *catch_up_dylib = NULL;

    /* inject pid/name dylib [-w[delay]] [-c dylib] */
    int positional = 0;
    const char *target = NULL, *dylib = NULL;
    bool usage_error = false;
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-' && argv[i][1] == 'w') {
            wait_for_process = true;
            delay = atoi(argv[i] + 2);
        }
        else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            catch_up_dylib = argv[++i];
        }
        else if (positional == 0) {
            target = argv[i];
            positional++;
        }
        else if (positional == 1) {
            dylib = argv[i];
            positional++;
        }
        else {
            usage_error = true;
        }
    }

    if (usage_error || positional != 2 || (catch_up_dylib && !wait_for_process)) {
        fprintf(stderr, "Usage: %s pid/name dylib [-w[delay] [-c dylib]]\n", argv[0]);
        exit(-1);
    }

    mach_port_t task = 0;
    int pid = atoi(target);
    bool waited = false;
    if (pid == 0) {
        do {
            fprintf(stderr, "Searching...\n");
            if (strlen(target) > 16) {
                fprintf(stderr, "Searching for process by name is currently not supported "
                                "for names longer than 16 characters. Use PID instead. \n");
                exit(-1);
            }

            int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
            size_t buf_size = 0;

            if (sysctl(mib, sizeof(mib) / sizeof(mib[0]), NULL, &buf_size, NULL, 0) < 0) {
                perror("Failure calling sysctl");
                return errno;
            }

            struct kinfo_proc *kprocbuf = malloc(buf_size);
            if (sysctl(mib, sizeof(mib) / sizeof(mib[0]), kprocbuf, &buf_size, NULL, 0) < 0) {
                perror("Failure calling sysctl");
                return errno;
            }

            size_t count = buf_size / sizeof(kprocbuf[0]);
            for (int i = 0; i < count; i++) {
                if (strcmp(kprocbuf[i].kp_proc.p_comm, target) == 0) {
                    pid = kprocbuf[i].kp_proc.p_pid;
                    break;
                }
            }

            free(kprocbuf);
            /* Mavericks port: poll gently while waiting (this runs at boot). */
            if (pid == 0 && wait_for_process) {
                waited = true;
                usleep(100000);
            }
        } while (pid == 0 && wait_for_process);
    }

    else if (wait_for_process) {
        fprintf(stderr, "-w must be used with a process name, not PID\n");
        exit(-1);
    }

    if (pid == 0) {
        fprintf(stderr, "Failed to find process named %s.\n", target);
        exit(-1);
    }

    /* A fresh process: started since we began waiting, or very recently. */
    bool fresh = waited || time(NULL) - process_start_time(pid) < FRESH_SECONDS;

    if (delay) {
        sleep(delay);
    }

    fprintf(stderr, "Injecting to process %d\n", pid);

    const char *error = wait_for_process ? inject_verified(pid, dylib) : inject_to_pid(pid, dylib, true);
    if (error) {
        fprintf(stderr, "Injection failed: %s\n", error);
        exit(1);
    }

    if (catch_up_dylib && fresh) {
        usleep(500000);   /* the dylib is listed as dyld maps it; let its initializer (the hook) finish */
        catch_up(catch_up_dylib, pid);
    }

    return 0;
}
