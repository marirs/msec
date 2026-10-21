// msec's App Store fixture: the main executable uses five protected resources, each with a
// different state of its purpose string in Info.plist (see ../build_store.sh).
#import <AVFoundation/AVFoundation.h>
#import <Contacts/Contacts.h>
#import <CoreLocation/CoreLocation.h>
#import <CoreMotion/CoreMotion.h>
#import <Foundation/Foundation.h>

int main(int argc, char *argv[]) {
    @autoreleasepool {
        // NSContactsUsageDescription is missing.
        CNContactStore *contacts = [[CNContactStore alloc] init];
        // NSLocationWhenInUseUsageDescription is blank.
        CLLocationManager *location = [[CLLocationManager alloc] init];
        [location requestWhenInUseAuthorization];
        // NSCameraUsageDescription is present.
        AVCaptureDevice *camera = [AVCaptureDevice defaultDeviceWithMediaType:AVMediaTypeVideo];
        // NSMotionUsageDescription is an integer.
        CMPedometer *pedometer = [[CMPedometer alloc] init];
        NSLog(@"%@ %@ %@ %@", contacts, location, camera, pedometer);
    }
    return 0;
}
