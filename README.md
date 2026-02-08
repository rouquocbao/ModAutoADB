### packages/modules/adb/daemon/main.cpp
thay đoạn
```
#if defined(__ANDROID__)

    // If we're on userdebug/eng or the device is unlocked, permit no-authentication.

    bool device_unlocked = "orange" == android::base::GetProperty("ro.boot.verifiedbootstate", "");

    if (__android_log_is_debuggable() || device_unlocked) {

        auth_required = android::base::GetBoolProperty("ro.adb.secure", false);

#if defined(__ANDROID_RECOVERY__)

        auth_required &= android::base::GetBoolProperty("ro.adb.secure.recovery", true);

#endif

    }

#endif
```

Bằng đoạn:
```
#if defined(__ANDROID__)
    // Force authentication to be disabled for internal ROM
    auth_required = false;
    
    // Chúng ta comment hoặc xóa các dòng kiểm tra cũ để tránh ghi đè giá trị false
    /*
    bool device_unlocked = "orange" == android::base::GetProperty("ro.boot.verifiedbootstate", "");
    if (__android_log_is_debuggable() || device_unlocked) {
        auth_required = android::base::GetBoolProperty("ro.adb.secure", false);
    }
    */
#endif
```
