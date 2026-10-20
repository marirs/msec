// Swift: the Swift runtime's retain and release are imported.
final class Box { let value: Int; init(_ value: Int) { self.value = value } }
let boxes = (0..<Int(CommandLine.arguments.count)).map { Box($0) }
print(boxes.map(\.value).reduce(0, +))
