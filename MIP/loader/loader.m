#include <Foundation/Foundation.h>
#include <unistd.h>
#include <stdio.h>
#include <mach-o/dyld.h>
#include <sys/syslimits.h>
#include <dlfcn.h>
#include <execinfo.h>
#include <pthread.h>
#include <objc/runtime.h>

#include "loader.h"
#include "simbl_compat.h"

#define objc_collectingEnabled() (@selector(retain) == @selector(release))


/* Exported so they can be used by loaded bundles */
const char *MIP_loader_path(void)
{
    Dl_info info;
    dladdr("", &info); // Get own info
    return info.dli_fname;
}

const char *MIP_root_path(void)
{
    static char *ret = NULL;
    if (ret) return ret;
        
    ret = strdup(MIP_loader_path());
    *strrchr(ret, '/') = 0;
    return ret;
}

/* Mavericks port: MIP keeps no per-user data of its own. This is kept for
   bundles written for upstream MIP that store their settings here; sandboxed
   processes can't read it. */
const char *MIP_user_data_path(void)
{
    static char user_data_path[PATH_MAX] = "";

    if (!user_data_path[0]) {
        NSString *path = [NSHomeDirectory() stringByAppendingPathComponent:@"Library/Application Support/MIP"];
        [[NSFileManager defaultManager] createDirectoryAtPath:path withIntermediateDirectories:YES attributes:nil error:nil];
        strlcpy(user_data_path, path.fileSystemRepresentation, sizeof(user_data_path));
    }
    return user_data_path;
}

bool should_inject_bundle(NSBundle *tweakBundle,
                          NSString *mainExecutableName)
{
    NSDictionary *plist = tweakBundle.infoDictionary;
    bool blacklistMode = [plist[@"MIPUseBlacklistMode"] boolValue];
    
    // Skip tweak if a matching bundle is excluded
    for (NSString *entry in plist[@"MIPExcludedBundleNames"]) {
        if (CFBundleGetBundleWithIdentifier((CFStringRef)entry)) {
            // Match found; skip loading
            return false;
        }
    }
    
    // Check if process matches bundle filter
    for (NSString *entry in plist[@"MIPBundleNames"]) {
        if (CFBundleGetBundleWithIdentifier((CFStringRef)entry)) {
            // Match found; invert if blacklist mode enabled
            return !blacklistMode;
        }
    }
    
    // Check if process matches executable filter
    for (NSString *entry in plist[@"MIPExecutableNames"]) {
        if ([mainExecutableName isEqualToString:entry]) {
            // Match found; invert if blacklist mode enabled
            return !blacklistMode;
        }
    }
    
    // No match find, return true if we're in blacklist mode
    return blacklistMode;
}

static void load_bundles(void)
{
    @autoreleasepool {
        @try {

            NSFileManager *fm = NSFileManager.defaultManager;
            
            NSURL *tweakBundlesURL = [NSURL fileURLWithPath:[@(MIP_root_path()) stringByAppendingPathComponent:@"Bundles"]];
            NSArray *tweakBundles = [fm contentsOfDirectoryAtURL:tweakBundlesURL
                                      includingPropertiesForKeys:nil
                                                         options:NSDirectoryEnumerationSkipsHiddenFiles
                                                           error:nil];
            
            char executable_path[PATH_MAX];
            uint32_t executable_path_length = sizeof(executable_path);
            _NSGetExecutablePath(executable_path, &executable_path_length);
            
            NSString *executable_name = @(executable_path).lastPathComponent;
            NSMutableArray *simbl_plugins = [NSMutableArray array];
            
            // Enumerate tweak bundles and determine whether or not to load each
            for (NSURL *bundle_url in tweakBundles) {
                
                NSBundle *tweakBundle = [NSBundle bundleWithURL:bundle_url];

                /* Mavericks port: SIMBL plugins follow SIMBL's rules (simbl_compat.m). */
                if (MIP_is_simbl_plugin(tweakBundle)) {
                    [simbl_plugins addObject:tweakBundle];
                    continue;
                }

                bool should_inject = should_inject_bundle(tweakBundle,
                                                          executable_name);

                if (should_inject) {
                    bool tweakSupportsGC = [tweakBundle.infoDictionary[@"MIPSupportsGC"] boolValue];
                    if (objc_collectingEnabled() && !tweakSupportsGC) {
                        // Skip loading if tweak doesn't support GC
                        NSLog(@"MIP: Bundle %@ was not loaded: %s required GC",
                              tweakBundle.bundlePath, executable_path);
                    }
                    else {
                        // Attempt loading tweak bundle
                        NSError *error = nil;
                        if (![tweakBundle loadAndReturnError:&error]) {
                            NSLog(@"MIP: Bundle %@ was not loaded: %@", tweakBundle.bundlePath, error);
                        }
                    }
                }
            }

            MIP_simbl_compat_init(simbl_plugins);
        }
        @catch (NSException *exception) {
            NSLog(@"MIP: Aborting load due to exception: %@\n%@",
                  exception, exception.callStackSymbols);
        }
    }
}

/* Mavericks port: where the loader runs.

   launchservicesd injects the loader when a process checks in, into the
   thread that is checking in, blocked until it replies (find_check_in_thread,
   injector/inject/inject.c) - so the loader runs at a known point. In an
   application that is its main thread (in -[NSApplication init], or from
   HIToolbox in a Carbon app), and bundles load there and then.

   A view service (an XPC service with an NSApplication, such as the save panel
   AppKit shows for sandboxed apps) checks in from a background queue, before
   it has an application: there the loader waits for -[NSApplication init],
   where an application's bundles load, and loads them on the main thread
   then. (Loading them on the main thread at another moment let the work the
   service's client had asked for run before NSApplicationMain: the save panel
   service exited, and Preview hung waiting for its Export panel.) A process
   without AppKit that checks in from a background thread gets its bundles
   from the main queue, between events.

   Injected by other means - by hand with `inject`, or caught up at boot, into
   an application already running - the loader loads at once (or, before the
   application exists, at -[NSApplication init]). */

static bool running_inside_check_in(void)
{
    void *frames[256];
    int count = backtrace(frames, 256);
    for (int i = 0; i < count; i++) {
        Dl_info info;
        if (dladdr(frames[i], &info) && info.dli_sname && strcmp(info.dli_sname, "_LSApplicationCheckIn") == 0) return true;
    }
    return false;
}

static id (*original_application_init)(id, SEL);

static id application_init(id self, SEL _cmd)
{
    self = original_application_init(self, _cmd);
    static bool loaded = false;
    if (self && !loaded && [NSThread isMainThread]) {
        loaded = true;
        load_bundles();
    }
    return self;
}

static bool load_at_application_init(void)
{
    Class application = objc_getClass("NSApplication");
    id *app = (id *)dlsym(RTLD_DEFAULT, "NSApp");
    if (!application || !app || *app) return false;
    Method init = class_getInstanceMethod(application, @selector(init));
    if (!init) return false;
    original_application_init = (id (*)(id, SEL))method_setImplementation(init, (IMP)application_init);
    return true;
}

static void __attribute__((constructor)) loader(void)
{
    /* Mavericks port: nothing is loaded into setuid/setgid processes (see
       process_is_setugid in injector/inject/inject.c, which should already
       have kept the loader out; this covers manual injection too). */
    if (issetugid()) return;

    bool main_thread = pthread_main_np() != 0;
    if (main_thread && running_inside_check_in()) {   /* an application checking in */
        load_bundles();
        return;
    }
    if (load_at_application_init()) return;           /* AppKit, no application yet */
    if (!main_thread) {
        dispatch_async(dispatch_get_main_queue(), ^{ load_bundles(); });
        return;
    }
    load_bundles();                                   /* injected into a running application */
}
