// Objective-C with manual reference counting: release is sent as a message, not as a call to
// the ARC runtime (the build disables clang's conversion of such messages to runtime calls).
#import <Foundation/Foundation.h>

int main(void) {
    NSString *text = [[NSString alloc] initWithFormat:@"%d", 42];
    NSLog(@"%@", text);
    [text release];
    return 0;
}
