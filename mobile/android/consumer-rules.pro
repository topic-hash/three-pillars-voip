# Consumer ProGuard rules for Three Pillars VoIP AAR
# These rules are applied to apps that depend on this library.

# UniFFI generated code
-keep class com.threepillars.voip.** { *; }

# JNA
-dontwarn com.sun.jna.**
