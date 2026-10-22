// msec's iOS security fixture (build_security.sh): each call the crypto, storage, WebView and
// logging checks look for, reached from main so the linker keeps it.
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>

// Writes to the unified system log.
static void LogToken(NSString *token) { NSLog(@"token %@", token); }

static void LogFormat(NSString *format, ...) {
  va_list arguments;
  va_start(arguments, format);
  NSLogv(format, arguments);
  va_end(arguments);
}

// Standard output.
static void PrintCount(int count) { printf("count %d\n", count); }

// Files readable while the device is locked.
static void WriteUnprotected(NSData *data, NSString *path) {
  [[NSFileManager defaultManager] createFileAtPath:path
                                          contents:data
                                        attributes:@{NSFileProtectionKey : NSFileProtectionNone}];
  [[NSURL fileURLWithPath:path] setResourceValue:NSURLFileProtectionNone
                                          forKey:NSURLFileProtectionKey
                                           error:nil];
}

// Keychain items readable while the device is locked (deprecated since iOS 12).
static void StoreAlways(NSData *secret, BOOL thisDeviceOnly) {
  CFStringRef accessible =
      thisDeviceOnly ? kSecAttrAccessibleAlwaysThisDeviceOnly : kSecAttrAccessibleAlways;
  SecItemAdd((__bridge CFDictionaryRef) @{
    (__bridge id)kSecClass : (__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecValueData : secret,
    (__bridge id)kSecAttrAccessible : (__bridge id)accessible
  },
             NULL);
}

// The deprecated web view (App Store Connect refuses it: ITMS-90809).
static UIView *LegacyWebView(void) { return [[UIWebView alloc] initWithFrame:CGRectZero]; }

// File URL pages allowed to read other files and any origin, by key-value coding.
static WKWebView *RelaxedWebView(void) {
  WKWebViewConfiguration *configuration = [[WKWebViewConfiguration alloc] init];
  [configuration.preferences setValue:@YES forKey:@"allowFileAccessFromFileURLs"];
  [configuration setValue:@YES forKey:@"allowUniversalAccessFromFileURLs"];
  return [[WKWebView alloc] initWithFrame:CGRectZero configuration:configuration];
}

int main(int argc, char *argv[]) {
  @autoreleasepool {
    NSString *argument = argc > 1 ? @(argv[1]) : @"none";
    NSData *data = [argument dataUsingEncoding:NSUTF8StringEncoding];
    LogToken(argument);
    LogFormat(@"%@ %d", argument, argc);
    PrintCount(argc);
    WriteUnprotected(data, argument);
    StoreAlways(data, argc > 2);
    return LegacyWebView() == nil || RelaxedWebView() == nil;
  }
}
