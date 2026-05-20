# UniFFI generated Kotlin bindings are safe to keep as-is
-keep class com.threepillars.voip.** { *; }

# Rust FFI functions
-keepclasseswithmembernames class * {
    native <methods>;
}

# JNA callback interfaces
-keep class * implements com.sun.jna.Callback {
    *;
}
