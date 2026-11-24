/* Mavericks port: SIMBL plugin compatibility.

   A bundle in MIP's Bundles folder whose Info.plist has no MIP filter keys
   (MIPBundleNames, MIPExecutableNames, MIPUseBlacklistMode) but has SIMBL's
   is a SIMBL plugin. It is loaded with the same rules as SIMBL 0.13.9 (w0lf's
   build, the last one for 10.9):

    - SIMBLTargetApplications: array of dictionaries. An entry matches when
        BundleIdentifier is the app's identifier or "*", and
        TargetApplicationPath (optional) equals the app's bundle path, and
        every RequiredFrameworks entry {BundleIdentifier, BundlePath (optional)}
        is loaded (at that path), and
        the app's CFBundleVersion, as an integer, is within
        MinBundleVersion / MaxBundleVersion (optional, integers).
    - SIMBLApplicationIdentifier (deprecated): array of identifiers or "*".
    - After loading, +install is sent to the principal class if it responds.

   Like SIMBLAgent, only applications are considered (not XPC services or
   other helpers - including view services, which report their client app as
   their main bundle), and osascript, Google Chrome Helper and loginwindow are
   skipped.

   SIMBL plugins were injected with an Apple Event after the application had
   finished launching, and many depend on that (menus, windows, the app
   delegate), so by default they are loaded on
   NSApplicationDidFinishLaunchingNotification. A plugin can opt into loading
   at MIP's injection point instead - inside -[NSApplication init], before the
   main menu, delegate or any window exists - with this in its Info.plist:

       <key>MIPLoadEarly</key>
       <true/>

   If the process has already finished launching (e.g. a manual `inject`),
   every plugin is loaded right away. */

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <sys/syslimits.h>
#import "simbl_compat.h"

#define objc_collectingEnabled() (@selector(retain) == @selector(release))

static NSArray *gPlugins;

BOOL MIP_is_simbl_plugin(NSBundle *bundle)
{
    NSDictionary *info = bundle.infoDictionary;
    if (info[@"MIPBundleNames"] || info[@"MIPExecutableNames"] || info[@"MIPUseBlacklistMode"]) return NO;
    return info[@"SIMBLTargetApplications"] || info[@"SIMBLApplicationIdentifier"];
}

static BOOL SIMBLTargetMatches(NSDictionary *target, NSBundle *app, NSBundle *plugin)
{
    if (![target isKindOfClass:[NSDictionary class]]) return NO;

    NSString *identifier = target[@"BundleIdentifier"];
    if (![identifier isKindOfClass:[NSString class]]) return NO;
    if (![identifier isEqualToString:@"*"] && ![identifier isEqualToString:app.bundleIdentifier]) return NO;

    NSString *appPath = target[@"TargetApplicationPath"];
    if ([appPath isKindOfClass:[NSString class]] && ![appPath isEqualToString:app.bundlePath]) return NO;

    NSArray *frameworks = target[@"RequiredFrameworks"];
    if ([frameworks isKindOfClass:[NSArray class]]) {
        for (NSDictionary *framework in frameworks) {
            if (![framework isKindOfClass:[NSDictionary class]]) return NO;
            NSBundle *loaded = [NSBundle bundleWithIdentifier:framework[@"BundleIdentifier"]];
            if (!loaded) return NO;
            NSString *path = framework[@"BundlePath"];
            if ([path isKindOfClass:[NSString class]] && ![path isEqualToString:loaded.bundlePath]) return NO;
        }
    }

    id minVersion = target[@"MinBundleVersion"];
    id maxVersion = target[@"MaxBundleVersion"];
    if (minVersion || maxVersion) {
        int appVersion = [[app objectForInfoDictionaryKey:@"CFBundleVersion"] intValue];
        if ((minVersion && appVersion < [minVersion intValue]) ||
            (maxVersion && appVersion > [maxVersion intValue])) {
            NSLog(@"MIP: %@ (version %d) has not been tested with the SIMBL plugin %@; it was not loaded.",
                  app.bundleIdentifier, appVersion, plugin.bundleIdentifier);
            return NO;
        }
    }
    return YES;
}

static BOOL SIMBLShouldLoad(NSBundle *plugin, NSBundle *app)
{
    NSArray *targets = [plugin objectForInfoDictionaryKey:@"SIMBLTargetApplications"];
    if ([targets isKindOfClass:[NSArray class]]) {
        for (NSDictionary *target in targets) {
            if (SIMBLTargetMatches(target, app, plugin)) return YES;
        }
        return NO;
    }

    NSArray *identifiers = [plugin objectForInfoDictionaryKey:@"SIMBLApplicationIdentifier"];
    if ([identifiers isKindOfClass:[NSArray class]]) {
        for (NSString *identifier in identifiers) {
            if ([identifier isKindOfClass:[NSString class]] &&
                ([identifier isEqualToString:@"*"] || [identifier isEqualToString:app.bundleIdentifier])) {
                return YES;
            }
        }
    }
    return NO;
}

static BOOL SIMBLProcessIsEligible(NSBundle *app)
{
    NSString *identifier = app.bundleIdentifier;
    if (!identifier) return NO;

    // SIMBLAgent only ever targeted applications.
    if (![[app.bundlePath pathExtension] isEqualToString:@"app"]) return NO;

    // ...and only their own processes. A view service (an XPC service such as
    // the save panel AppKit shows for a sandboxed app) reports its client app
    // as its main bundle, but runs an executable of its own elsewhere.
    char executable[PATH_MAX];
    uint32_t length = sizeof(executable);
    if (_NSGetExecutablePath(executable, &length) != 0) return NO;
    NSString *executablePath = [@(executable) stringByResolvingSymlinksInPath];
    NSString *bundlePath = [app.bundlePath stringByResolvingSymlinksInPath];
    if (![executablePath hasPrefix:[bundlePath stringByAppendingString:@"/"]]) return NO;

    NSString *name = [[NSProcessInfo processInfo] processName];
    if ([@[@"osascript", @"Google Chrome Helper"] containsObject:name]) return NO;
    if ([identifier isEqualToString:@"com.apple.loginwindow"]) return NO;
    return YES;
}

typedef enum { SIMBLEarlyPlugins, SIMBLRemainingPlugins } SIMBLPhase;

static BOOL SIMBLWantsEarlyLoad(NSBundle *plugin)
{
    id early = [plugin objectForInfoDictionaryKey:@"MIPLoadEarly"];
    return [early respondsToSelector:@selector(boolValue)] && [early boolValue];
}

static void SIMBLLoadPlugins(SIMBLPhase phase)
{
    static BOOL done[2] = { NO, NO };
    if (done[phase]) return;
    done[phase] = YES;

    @autoreleasepool {
        @try {
            NSBundle *app = [NSBundle mainBundle];
            if (!SIMBLProcessIsEligible(app)) return;

            for (NSBundle *plugin in gPlugins) {
                NSString *identifier = plugin.bundleIdentifier;
                if (SIMBLWantsEarlyLoad(plugin) != (phase == SIMBLEarlyPlugins)) continue;
                if (!SIMBLShouldLoad(plugin, app)) continue;

                if (objc_collectingEnabled()) {
                    NSLog(@"MIP: SIMBL plugin %@ was not loaded: %@ uses garbage collection", identifier, identifier);
                    continue;
                }

                NSError *error = nil;
                if (![plugin loadAndReturnError:&error]) {
                    NSLog(@"MIP: failed to load the SIMBL plugin %@: %@", identifier, error);
                    continue;
                }
                Class principal = [plugin principalClass];
                if ([principal respondsToSelector:@selector(install)]) {
                    @try {
                        ((void (*)(id, SEL))objc_msgSend)(principal, @selector(install));
                    }
                    @catch (NSException *exception) {
                        NSLog(@"MIP: SIMBL plugin %@ raised in +install: %@", identifier, exception);
                    }
                }
            }
        }
        @catch (NSException *exception) {
            NSLog(@"MIP: aborting SIMBL plugin loading due to exception: %@\n%@",
                  exception, exception.callStackSymbols);
        }
    }
}

static BOOL SIMBLApplicationHasFinishedLaunching(void)
{
    // Read the NSApp global rather than creating the application object.
    id *nsApp = (id *)dlsym(RTLD_DEFAULT, "NSApp");
    id app = nsApp ? *nsApp : nil;
    if (!app) return NO;
    return ((BOOL (*)(id, SEL))objc_msgSend)(app, sel_getUid("isRunning"));
}

void MIP_simbl_compat_init(NSArray *plugins)
{
    if (!plugins.count) return;
    gPlugins = [plugins copy];
    SIMBLLoadPlugins(SIMBLEarlyPlugins);
    if (SIMBLApplicationHasFinishedLaunching()) {
        SIMBLLoadPlugins(SIMBLRemainingPlugins);
        return;
    }
    __block id observer = [[NSNotificationCenter defaultCenter]
        addObserverForName:@"NSApplicationDidFinishLaunchingNotification"
                    object:nil
                     queue:nil
                usingBlock:^(NSNotification *note) {
                    [[NSNotificationCenter defaultCenter] removeObserver:observer];
                    SIMBLLoadPlugins(SIMBLRemainingPlugins);
                }];
}
