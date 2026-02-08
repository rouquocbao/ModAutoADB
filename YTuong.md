# Hướng dẫn Disable ADB Authentication trong AOSP

## Mục đích

Hướng dẫn này mô tả cách sửa đổi source code AOSP để disable xác thực RSA USB debugging, cho phép kết nối ADB tự động mà không cần người dùng xác nhận "Allow USB debugging" trên thiết bị.

## Tổng quan

Android Debug Bridge (ADB) mặc định yêu cầu xác thực RSA key để đảm bảo bảo mật. Khi kết nối lần đầu, thiết bị sẽ hiển thị dialog yêu cầu người dùng xác nhận. Việc disable authentication sẽ bỏ qua bước này, cho phép kết nối tự động.

## Các file cần sửa đổi

### File chính: `packages/modules/adb/daemon/auth.cpp`

File này chứa logic xác thực ADB, bao gồm:
- Biến `auth_required` - flag điều khiển việc yêu cầu authentication
- Function `adbd_auth_verify()` - xác thực RSA signature
- Function `adbd_tls_verify_cert()` - xác thực TLS certificate

## Các bước thực hiện

### Bước 1: Disable authentication flag

**Vị trí:** Dòng 66 trong `auth.cpp`

**Thay đổi:**
```cpp
// Trước:
bool auth_required = true;

// Sau:
bool auth_required = false;  // Disabled to allow auto-connect without RSA authentication
```

**Mục đích:** Tắt yêu cầu authentication ở mức global.

### Bước 2: Bypass RSA signature verification

**Vị trí:** Function `adbd_auth_verify()` (khoảng dòng 156-194)

**Thay đổi:**
```cpp
bool adbd_auth_verify(const char* token, size_t token_size, const std::string& sig,
                      std::string* auth_key) {
    // Auto-accept all authentication to allow connection without RSA key
    // This bypasses RSA verification to allow auto-connect without user confirmation
    auth_key->clear();
    return true;  // Always return true to bypass RSA verification

#if 0
    // Original authentication code (disabled)
    // ... code gốc được comment lại ...
#endif
}
```

**Mục đích:** Luôn trả về `true` để bỏ qua kiểm tra RSA signature, cho phép mọi kết nối được chấp nhận.

### Bước 3: Bypass TLS certificate verification

**Vị trí:** Function `adbd_tls_verify_cert()` (khoảng dòng 301-356)

**Thay đổi:**
```cpp
int adbd_tls_verify_cert(X509_STORE_CTX* ctx, std::string* auth_key) {
    // Auto-accept all TLS certificates to allow connection without RSA key
    // This bypasses certificate verification to allow auto-connect without user confirmation
    LOG(INFO) << __func__ << ": auth disabled, accepting all certificates";
    return 1;  // Always return 1 (success) to bypass certificate verification

#if 0
    // Original TLS certificate verification code (disabled)
    // ... code gốc được comment lại ...
#endif
}
```

**Mục đích:** Luôn trả về `1` (success) để chấp nhận mọi TLS certificate, bỏ qua kiểm tra certificate.

## Cách áp dụng cho project AOSP khác

### 1. Tìm file auth.cpp

File thường nằm tại:
```
packages/modules/adb/daemon/auth.cpp
```

Hoặc trong các phiên bản AOSP cũ:
```
system/core/adb/daemon/auth.cpp
```

### 2. Xác định các function cần sửa

Sử dụng grep để tìm:
```bash
grep -n "auth_required\|adbd_auth_verify\|adbd_tls_verify_cert" packages/modules/adb/daemon/auth.cpp
```

### 3. Áp dụng các thay đổi

- **Option 1:** Sửa trực tiếp như hướng dẫn trên
- **Option 2:** Sử dụng patch file (xem phần dưới)

### 4. Build lại adbd

```bash
# Trong thư mục AOSP root
source build/envsetup.sh
lunch <target>
mmm packages/modules/adb
# hoặc
m adbd
```

### 5. Deploy lên thiết bị

```bash
adb push out/target/product/<device>/system/bin/adbd /system/bin/adbd
adb shell chmod 755 /system/bin/adbd
adb reboot
```

## Tạo patch file (khuyến nghị)

Để dễ dàng áp dụng cho nhiều project, tạo patch file:

```bash
# Tạo patch
cd packages/modules/adb
git diff daemon/auth.cpp > disable_adb_auth.patch

# Áp dụng patch cho project khác
cd <other_aosp_project>/packages/modules/adb
git apply disable_adb_auth.patch
```

## So sánh với binary patch

### Binary patch (như QUANG-TUNG-adbd)

**Ưu điểm:**
- Không cần build lại từ source
- Có thể áp dụng trực tiếp lên binary

**Nhược điểm:**
- Khó maintain và update
- Có thể bị phát hiện bởi security checks
- Không thể revert dễ dàng

### Source code patch (cách này)

**Ưu điểm:**
- Dễ maintain và update
- Có thể build lại với các version khác nhau
- Code rõ ràng, dễ hiểu
- Có thể revert bằng cách uncomment code gốc

**Nhược điểm:**
- Cần build lại từ source
- Cần có môi trường build AOSP

## Lưu ý bảo mật

⚠️ **QUAN TRỌNG:** Việc disable ADB authentication sẽ:

1. **Vô hiệu hóa bảo mật:** Bất kỳ ai có quyền truy cập USB đều có thể kết nối ADB mà không cần xác nhận
2. **Rủi ro bảo mật:** Thiết bị dễ bị tấn công qua USB
3. **Không phù hợp production:** Chỉ nên dùng trong:
   - Development environment
   - Testing environment
   - Internal builds
   - Rooted devices cho mục đích nghiên cứu

## Cách revert (khôi phục)

Để khôi phục authentication:

1. Đổi `auth_required = false` thành `auth_required = true`
2. Uncomment code gốc (đổi `#if 0` thành `#if 1`)
3. Xóa các dòng return sớm
4. Build lại và deploy

## Troubleshooting

### Vấn đề: Vẫn yêu cầu authentication

**Nguyên nhân có thể:**
- Property `ro.adb.secure` được set trong build config
- File `main.cpp` có logic override `auth_required`

**Giải pháp:**
Kiểm tra `daemon/main.cpp` (khoảng dòng 214):
```cpp
auth_required = android::base::GetBoolProperty("ro.adb.secure", false);
```
Có thể cần sửa logic này hoặc set property `ro.adb.secure=0` trong build.

### Vấn đề: Build lỗi

**Nguyên nhân:**
- Code syntax error
- Missing includes

**Giải pháp:**
- Kiểm tra lại các thay đổi
- Đảm bảo comment đúng format `#if 0` / `#endif`
- Chạy `read_lints` để kiểm tra lỗi

## Tài liệu tham khảo

- [AOSP ADB Source Code](https://android.googlesource.com/platform/packages/modules/adb/)
- [ADB Protocol Documentation](https://android.googlesource.com/platform/packages/modules/adb/+/HEAD/protocol.txt)
- [Android Security - ADB](https://source.android.com/docs/security/features/adb)

## License

Các thay đổi này dựa trên AOSP source code, tuân theo Apache License 2.0.

## Tác giả

Hướng dẫn này được tạo dựa trên phân tích và so sánh:
- `NGUYEN-GOC-adbd`: Binary gốc với authentication enabled
- `QUANG-TUNG-adbd`: Binary đã patch để disable authentication

## Changelog

- **2024-02-08**: Tạo hướng dẫn ban đầu
  - Disable `auth_required` flag
  - Bypass `adbd_auth_verify()`
  - Bypass `adbd_tls_verify_cert()`
