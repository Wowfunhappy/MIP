#import <Foundation/Foundation.h>

/* Mavericks port: SIMBL plugin compatibility (simbl_compat.m). */
/* Whether a bundle in MIP's Bundles folder is a SIMBL plugin. */
BOOL MIP_is_simbl_plugin(NSBundle *bundle);

/* Loads the given SIMBL plugins following SIMBL's rules and timing. */
void MIP_simbl_compat_init(NSArray *plugins);
