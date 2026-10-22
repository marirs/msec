// msec's clean iOS security fixture (build_security.sh): the safe counterpart of each call in
// ../main.m.
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <WebKit/WebKit.h>
#import <os/log.h>

// Unified logging, the dynamic value private (redacted unless a profile reveals it).
static void LogToken(NSString *token) {
  os_log(OS_LOG_DEFAULT, "token %{private}@", token);
}

// Complete protection: unreadable while the device is locked.
static void WriteProtected(NSData *data, NSString *path) {
  [[NSFileManager defaultManager]
      createFileAtPath:path
              contents:data
            attributes:@{NSFileProtectionKey : NSFileProtectionComplete}];
}

static void StoreWhenUnlocked(NSData *secret) {
  SecItemAdd((__bridge CFDictionaryRef) @{
    (__bridge id)kSecClass : (__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecValueData : secret,
    (__bridge id)kSecAttrAccessible : (__bridge id)kSecAttrAccessibleWhenUnlockedThisDeviceOnly
  },
             NULL);
}

// WKWebView with its default file origin rules.
static WKWebView *DefaultWebView(void) {
  return [[WKWebView alloc] initWithFrame:CGRectZero
                            configuration:[[WKWebViewConfiguration alloc] init]];
}

int main(int argc, char *argv[]) {
  @autoreleasepool {
    NSString *argument = argc > 1 ? @(argv[1]) : @"none";
    NSData *data = [argument dataUsingEncoding:NSUTF8StringEncoding];
    LogToken(argument);
    WriteProtected(data, argument);
    StoreWhenUnlocked(data);
    return DefaultWebView() == nil;
  }
}
