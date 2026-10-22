// msec's iOS store-lead fixture (build_store_leads.sh): Stripe without StoreKit, Google Sign-In
// without Sign in with Apple, account creation without deletion, and a private framework both
// linked and named for dlopen.
#import <Foundation/Foundation.h>
#import <dlfcn.h>

@interface GIDSignIn : NSObject
@end

@protocol FixtureAuth
- (void)createUserWithEmail:(NSString *)email password:(NSString *)password completion:(id)completion;
@end

extern void STPStripeStart(void);
extern void AppchkFixturePrivateCall(void);

int main(int argc, char *argv[]) {
  @autoreleasepool {
    [GIDSignIn new];
    STPStripeStart();
    id<FixtureAuth> auth = (id<FixtureAuth>)[NSObject new];
    if (argc > 5) {
      [auth createUserWithEmail:@"user@example.com" password:@"x" completion:nil];
      AppchkFixturePrivateCall();
    }
    void *handle =
        dlopen("/System/Library/PrivateFrameworks/FrontBoardServices.framework/FrontBoardServices",
               RTLD_LAZY);
    return handle == NULL;
  }
}
