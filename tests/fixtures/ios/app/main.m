// Main executable of msec's IPA fixture: Objective-C under ARC, linked against the fixture's
// framework, with a bounded string copy and a log call, so the Mach-O checks have imports,
// symbols and a stack protector to find.
#import <Foundation/Foundation.h>
#include <string.h>

int fixture_lib_answer(void);

int main(int argc, char *argv[]) {
    @autoreleasepool {
        char buffer[16];
        strncpy(buffer, argc > 1 ? argv[1] : "fixture", sizeof buffer - 1);
        buffer[sizeof buffer - 1] = '\0';
        NSLog(@"%s %d", buffer, fixture_lib_answer());
    }
    return 0;
}
