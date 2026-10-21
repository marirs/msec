// A framework using Bluetooth: the app's Info.plist must carry its purpose string, and does not.
#import <CoreBluetooth/CoreBluetooth.h>

id fixture_bluetooth(void) {
    return [[CBCentralManager alloc] initWithDelegate:nil queue:nil];
}
