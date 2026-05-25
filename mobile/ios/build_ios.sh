/// Build script to compile voip-ffi for iOS targets.
///
/// Usage:
///   ./build_ios.sh [--release] [--simulator]
///
/// Options:
///   --release     Build in release mode (default: debug)
///   --simulator   Build for iOS Simulator (aarch64-apple-ios-sim)
///                 Default is device (aarch64-apple-ios)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_MODE="debug"
TARGET="aarch64-apple-ios"

while [[ $# -gt 0 ]]; do
    case $1 in
        --release) BUILD_MODE="release"; shift ;;
        --simulator) TARGET="aarch64-apple-ios-sim"; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

echo "Building voip-ffi for $TARGET ($BUILD_MODE)..."

cd "$PROJECT_ROOT"

# Build the Rust library
if [ "$BUILD_MODE" = "release" ]; then
    cargo build --release -p voip-ffi --target "$TARGET"
else
    cargo build -p voip-ffi --target "$TARGET"
fi

# Generate Swift bindings
echo "Generating Swift bindings..."
LIB_PATH="target/$TARGET/$BUILD_MODE/libvoip_ffi.a"
OUTPUT_DIR="$SCRIPT_DIR/Sources"

mkdir -p "$OUTPUT_DIR"

cargo run --bin uniffi-bindgen generate \
    --library "$LIB_PATH" \
    --language swift \
    --out-dir "$OUTPUT_DIR"

echo "Build complete!"
echo "  Library: $LIB_PATH"
echo "  Swift bindings: $OUTPUT_DIR"
echo ""
echo "To create XCFramework, run:"
echo "  xcodebuild -create-xcframework \\"
echo "    -library target/aarch64-apple-ios/$BUILD_MODE/libvoip_ffi.a \\"
echo "    -headers $OUTPUT_DIR \\"
echo "    -library target/aarch64-apple-ios-sim/$BUILD_MODE/libvoip_ffi.a \\"
echo "    -headers $OUTPUT_DIR \\"
echo "    -output $SCRIPT_DIR/ThreePillarsVoIP.xcframework"
