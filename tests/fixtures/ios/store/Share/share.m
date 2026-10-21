// An app extension using speech recognition: its own Info.plist must carry the purpose string;
// only the app's does.
#import <Foundation/Foundation.h>
#import <Speech/Speech.h>

int main(int argc, char *argv[]) {
    @autoreleasepool {
        NSLog(@"%@", [[SFSpeechRecognizer alloc] init]);
    }
    return 0;
}
