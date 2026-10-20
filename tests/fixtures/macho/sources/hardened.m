// Objective-C under ARC with objects it retains and releases (so ARC's runtime calls are
// imported), a bounded copy into a stack buffer (so the stack protector is used), and a
// fortified memcpy (so a __memcpy_chk import appears at -O1 and above).
#import <Foundation/Foundation.h>
#include <string.h>

int main(int argc, char *argv[]) {
    @autoreleasepool {
        char buffer[32];
        strncpy(buffer, argc > 1 ? argv[1] : "fixture", sizeof buffer - 1);
        buffer[sizeof buffer - 1] = '\0';
        char copy[32];
        memcpy(copy, buffer, strlen(buffer) + 1);
        NSMutableArray<NSString *> *words = [NSMutableArray array];
        [words addObject:[NSString stringWithFormat:@"%s", copy]];
        NSLog(@"%@ %lu", words.firstObject, (unsigned long)words.count);
    }
    return 0;
}
