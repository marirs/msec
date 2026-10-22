// msec's clean iOS security fixture, Swift part (build_security.sh): SHA-256 and unified
// logging with the value private.
import CryptoKit
import Foundation
import os

private let logger = Logger(subsystem: "dev.appchk.security", category: "fixture")

public func digest(_ data: Data) -> String {
    SHA256.hash(data: data).description
}

public func report(_ value: String) {
    logger.info("value \(value, privacy: .private)")
}
