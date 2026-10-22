// msec's iOS security fixture, Swift part (build_security.sh): CryptoKit's insecure hashes,
// Swift's printing functions and a relaxed WebView file origin set from Swift.
import CryptoKit
import Foundation
import WebKit

public func legacyDigests(_ data: Data) -> [String] {
    [Insecure.MD5.hash(data: data).description, Insecure.SHA1.hash(data: data).description]
}

public func report(_ value: String) {
    print("value", value)
    debugPrint(value)
}

public func relaxFileOrigin(_ configuration: WKWebViewConfiguration) {
    configuration.preferences.setValue(true, forKey: "allowFileAccessFromFileURLs")
}
