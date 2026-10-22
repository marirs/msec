// msec's clean iOS store-lead fixture (build_store_leads.sh): Stripe beside StoreKit, Google
// Sign-In beside Sign in with Apple, account creation with deletion, no private framework.
#import <AuthenticationServices/AuthenticationServices.h>
#import <Foundation/Foundation.h>
#import <StoreKit/StoreKit.h>

@interface GIDSignIn : NSObject
@end

@protocol FixtureAuth
- (void)createUserWithEmail:(NSString *)email password:(NSString *)password completion:(id)completion;
- (void)deleteWithCompletion:(id)completion;
@end

extern void STPStripeStart(void);

int main(int argc, char *argv[]) {
  @autoreleasepool {
    [GIDSignIn new];
    [ASAuthorizationAppleIDProvider new];
    STPStripeStart();
    [SKPaymentQueue defaultQueue];
    id<FixtureAuth> auth = (id<FixtureAuth>)[NSObject new];
    if (argc > 5) {
      [auth createUserWithEmail:@"user@example.com" password:@"x" completion:nil];
      [auth deleteWithCompletion:nil];
    }
    return 0;
  }
}
