// The privacy fixture's main executable: it uses one API of each required-reason category,
// so the scanner must find each, and its privacy manifest declares only some of them.
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#include <mach/mach_time.h>
#include <sys/mount.h>
#include <sys/stat.h>

int main(int argc, char *argv[]) {
    @autoreleasepool {
        // File timestamp (declared, C617.1).
        struct stat info;
        stat(argv[0], &info);
        // System boot time (declared with a reason code Apple does not define).
        uint64_t ticks = mach_absolute_time();
        NSTimeInterval uptime = [[NSProcessInfo processInfo] systemUptime];
        // Disk space (not declared).
        struct statfs volume;
        statfs("/", &volume);
        NSDictionary *attributes =
            [[NSFileManager defaultManager] attributesOfFileSystemForPath:@"/" error:nil];
        NSNumber *free = attributes[NSFileSystemFreeSize];
        // Active keyboards (not declared).
        NSArray *modes = [UITextInputMode activeInputModes];
        // User defaults (declared, CA92.1).
        [[NSUserDefaults standardUserDefaults] setDouble:uptime forKey:@"uptime"];
        return (int)(ticks + info.st_size + volume.f_bfree + free.intValue + modes.count) & 1;
    }
}
