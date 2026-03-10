### packages/modules/adb/daemon/auth.cpp
sửa:
```
/*
 * Copyright (C) 2012 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define TRACE_TAG AUTH

#include "sysdeps.h"

#include <resolv.h>
#include <stdio.h>
#include <string.h>

#include <algorithm>
#include <chrono>
#include <iomanip>
#include <map>
#include <memory>
#include <thread>

#include <adb/crypto/rsa_2048_key.h>
#include <adb/tls/adb_ca_list.h>
#include <adbd_auth.h>
#include <android-base/file.h>
#include <android-base/no_destructor.h>
#include <android-base/strings.h>
#include <crypto_utils/android_pubkey.h>
#include <openssl/obj_mac.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>

#include "adb.h"
#include "adb_auth.h"
#include "adb_io.h"
#include "adb_wifi.h"
#include "fdevent/fdevent.h"
#include "transport.h"
#include "types.h"

using namespace adb::crypto;
using namespace adb::tls;
using namespace std::chrono_literals;

static AdbdAuthContext* auth_ctx;

static RSA* rsa_pkey = nullptr;

static void adb_disconnected(void* unused, atransport* t);
static struct adisconnect adb_disconnect = {adb_disconnected, nullptr};

static android::base::NoDestructor<std::map<uint32_t, weak_ptr<atransport>>> transports;
static uint32_t transport_auth_id = 0;

bool auth_required = false;  // Disabled to allow auto-connect without RSA authentication
bool socket_access_allowed = true;

static void* transport_to_callback_arg(atransport* transport) {
    uint32_t id = transport_auth_id++;
    (*transports)[id] = transport->weak();
    return reinterpret_cast<void*>(id);
}

static atransport* transport_from_callback_arg(void* id) {
    uint64_t id_u64 = reinterpret_cast<uint64_t>(id);
    if (id_u64 > std::numeric_limits<uint32_t>::max()) {
        LOG(FATAL) << "transport_from_callback_arg called on out of range value: " << id_u64;
    }

    uint32_t id_u32 = static_cast<uint32_t>(id_u64);
    auto it = transports->find(id_u32);
    if (it == transports->end()) {
        LOG(ERROR) << "transport_from_callback_arg failed to find transport for id " << id_u32;
        return nullptr;
    }

    atransport* t = it->second.get();
    if (!t) {
        LOG(WARNING) << "transport_from_callback_arg found already destructed transport";
        return nullptr;
    }

    transports->erase(it);
    return t;
}

static void IteratePublicKeys(std::function<bool(std::string_view public_key)> f) {
    adbd_auth_get_public_keys(
            auth_ctx,
            [](void* opaque, const char* public_key, size_t len) {
                return (*static_cast<decltype(f)*>(opaque))(std::string_view(public_key, len));
            },
            &f);
}

bssl::UniquePtr<STACK_OF(X509_NAME)> adbd_tls_client_ca_list() {
    if (!auth_required) {
        return nullptr;
    }

    bssl::UniquePtr<STACK_OF(X509_NAME)> ca_list(sk_X509_NAME_new_null());

    IteratePublicKeys([&](std::string_view public_key) {
        // TODO: do we really have to support both ' ' and '\t'?
        std::vector<std::string> split = android::base::Split(std::string(public_key), " \t");
        uint8_t keybuf[ANDROID_PUBKEY_ENCODED_SIZE + 1];
        const std::string& pubkey = split[0];
        if (b64_pton(pubkey.c_str(), keybuf, sizeof(keybuf)) != ANDROID_PUBKEY_ENCODED_SIZE) {
            LOG(ERROR) << "Invalid base64 key " << pubkey;
            return true;
        }

        RSA* key = nullptr;
        if (!android_pubkey_decode(keybuf, ANDROID_PUBKEY_ENCODED_SIZE, &key)) {
            LOG(ERROR) << "Failed to parse key " << pubkey;
            return true;
        }
        bssl::UniquePtr<RSA> rsa_key(key);

        unsigned char* dkey = nullptr;
        int len = i2d_RSA_PUBKEY(rsa_key.get(), &dkey);
        if (len <= 0 || dkey == nullptr) {
            LOG(ERROR) << "Failed to encode RSA public key";
            return true;
        }

        uint8_t digest[SHA256_DIGEST_LENGTH];
        // Put the encoded key in the commonName attribute of the issuer name.
        // Note that the commonName has a max length of 64 bytes, which is less
        // than the SHA256_DIGEST_LENGTH.
        SHA256(dkey, len, digest);
        OPENSSL_free(dkey);

        auto digest_str = SHA256BitsToHexString(
                std::string_view(reinterpret_cast<const char*>(&digest[0]), sizeof(digest)));
        LOG(INFO) << "fingerprint=[" << digest_str << "]";
        auto issuer = CreateCAIssuerFromEncodedKey(digest_str);
        CHECK(bssl::PushToStack(ca_list.get(), std::move(issuer)));
        return true;
    });

    return ca_list;
}

bool adbd_auth_verify(const char* token, size_t token_size, const std::string& sig,
                      std::string* auth_key) {
    // Auto-accept all authentication to allow connection without RSA key
    // This bypasses RSA verification to allow auto-connect without user confirmation
    auth_key->clear();
    return true;  // Always return true to bypass RSA verification

#if 0
    // Original authentication code (disabled)
    bool authorized = false;

    IteratePublicKeys([&](std::string_view public_key) {
        // TODO: do we really have to support both ' ' and '\t'?
        std::vector<std::string> split = android::base::Split(std::string(public_key), " \t");
        uint8_t keybuf[ANDROID_PUBKEY_ENCODED_SIZE + 1];
        const std::string& pubkey = split[0];
        if (b64_pton(pubkey.c_str(), keybuf, sizeof(keybuf)) != ANDROID_PUBKEY_ENCODED_SIZE) {
            LOG(ERROR) << "Invalid base64 key " << pubkey;
            return true;
        }

        RSA* key = nullptr;
        if (!android_pubkey_decode(keybuf, ANDROID_PUBKEY_ENCODED_SIZE, &key)) {
            LOG(ERROR) << "Failed to parse key " << pubkey;
            return true;
        }

        bool verified =
                (RSA_verify(NID_sha1, reinterpret_cast<const uint8_t*>(token), token_size,
                            reinterpret_cast<const uint8_t*>(sig.c_str()), sig.size(), key) == 1);
        RSA_free(key);
        if (verified) {
            *auth_key = public_key;
            authorized = true;
            return false;
        }

        return true;
    });

    return authorized;
#endif
}

static bool adbd_auth_generate_token(void* token, size_t token_size) {
    FILE* fp = fopen("/dev/urandom", "re");
    if (!fp) return false;
    bool okay = (fread(token, token_size, 1, fp) == 1);
    fclose(fp);
    return okay;
}

void adbd_cloexec_auth_socket() {
    int fd = android_get_control_socket("adbd");
    if (fd == -1) {
        PLOG(ERROR) << "Failed to get adbd socket";
        return;
    }
    fcntl(fd, F_SETFD, FD_CLOEXEC);
}

static void adbd_auth_key_authorized(void* arg, uint64_t id) {
    LOG(INFO) << "adb client " << id << " authorized";
    fdevent_run_on_main_thread([=]() {
        auto* transport = transport_from_callback_arg(arg);
        if (!transport) {
            LOG(ERROR) << "authorization received for deleted transport (" << id << "), ignoring";
            return;
        }

        if (transport->auth_id.has_value()) {
            if (transport->auth_id.value() != id) {
                LOG(ERROR)
                        << "authorization received, but auth id doesn't match, ignoring (expected "
                        << transport->auth_id.value() << ", got " << id << ")";
                return;
            }
        } else {
            // Older versions (i.e. dogfood/beta builds) of libadbd_auth didn't pass the initial
            // auth id to us, so we'll just have to trust it until R ships and we can retcon this.
            transport->auth_id = id;
        }

        adbd_auth_verified(transport);
    });
}

static void adbd_key_removed(const char* public_key, size_t len) {
    // The framework removed the key from its keystore. We need to disconnect all
    // devices using that key. Search by t->auth_key
    std::string_view auth_key(public_key, len);
    kick_all_transports_by_auth_key(auth_key);
}

void adbd_auth_init(void) {
    AdbdAuthCallbacksV1 cb;
    cb.version = 1;
    cb.key_authorized = adbd_auth_key_authorized;
    cb.key_removed = adbd_key_removed;
    auth_ctx = adbd_auth_new(&cb);
    adbd_wifi_init(auth_ctx);
    std::thread([]() {
        adb_thread_setname("adbd auth");
        adbd_auth_run(auth_ctx);
        LOG(FATAL) << "auth thread terminated";
    }).detach();
}

void send_auth_request(atransport* t) {
    LOG(INFO) << "Calling send_auth_request...";

    if (!adbd_auth_generate_token(t->token, sizeof(t->token))) {
        PLOG(ERROR) << "Error generating token";
        return;
    }

    apacket* p = get_apacket();
    p->msg.command = A_AUTH;
    p->msg.arg0 = ADB_AUTH_TOKEN;
    p->msg.data_length = sizeof(t->token);
    p->payload.assign(t->token, t->token + sizeof(t->token));
    send_packet(p, t);
}

void adbd_auth_verified(atransport* t) {
    LOG(INFO) << "adb client authorized";
    handle_online(t);
    send_connect(t);
}

static void adb_disconnected(void* unused, atransport* t) {
    LOG(INFO) << "ADB disconnect";
    CHECK(t->auth_id.has_value());
    adbd_auth_notify_disconnect(auth_ctx, t->auth_id.value());
}

void adbd_auth_confirm_key(atransport* t) {
    LOG(INFO) << "prompting user to authorize key";
    t->AddDisconnect(&adb_disconnect);
    if (adbd_auth_prompt_user_with_id) {
        t->auth_id = adbd_auth_prompt_user_with_id(auth_ctx, t->auth_key.data(), t->auth_key.size(),
                                                   transport_to_callback_arg(t));
    } else {
        adbd_auth_prompt_user(auth_ctx, t->auth_key.data(), t->auth_key.size(),
                              transport_to_callback_arg(t));
    }
}

void adbd_notify_framework_connected_key(atransport* t) {
    t->auth_id = adbd_auth_notify_auth(auth_ctx, t->auth_key.data(), t->auth_key.size());
}

int adbd_tls_verify_cert(X509_STORE_CTX* ctx, std::string* auth_key) {
    // Auto-accept all TLS certificates to allow connection without RSA key
    // This bypasses certificate verification to allow auto-connect without user confirmation
    LOG(INFO) << __func__ << ": auth disabled, accepting all certificates";
    return 1;  // Always return 1 (success) to bypass certificate verification

#if 0
    // Original TLS certificate verification code (disabled)
    if (!auth_required) {
        // Any key will do.
        LOG(INFO) << __func__ << ": auth not required";
        return 1;
    }

    bool authorized = false;
    X509* cert = X509_STORE_CTX_get0_cert(ctx);
    if (cert == nullptr) {
        LOG(INFO) << "got null x509 certificate";
        return 0;
    }
    bssl::UniquePtr<EVP_PKEY> evp_pkey(X509_get_pubkey(cert));
    if (evp_pkey == nullptr) {
        LOG(INFO) << "got null evp_pkey from x509 certificate";
        return 0;
    }

    IteratePublicKeys([&](std::string_view public_key) {
        // TODO: do we really have to support both ' ' and '\t'?
        std::vector<std::string> split = android::base::Split(std::string(public_key), " \t");
        uint8_t keybuf[ANDROID_PUBKEY_ENCODED_SIZE + 1];
        const std::string& pubkey = split[0];
        if (b64_pton(pubkey.c_str(), keybuf, sizeof(keybuf)) != ANDROID_PUBKEY_ENCODED_SIZE) {
            LOG(ERROR) << "Invalid base64 key " << pubkey;
            return true;
        }

        RSA* key = nullptr;
        if (!android_pubkey_decode(keybuf, ANDROID_PUBKEY_ENCODED_SIZE, &key)) {
            LOG(ERROR) << "Failed to parse key " << pubkey;
            return true;
        }

        bool verified = false;
        bssl::UniquePtr<EVP_PKEY> known_evp(EVP_PKEY_new());
        EVP_PKEY_set1_RSA(known_evp.get(), key);
        if (EVP_PKEY_cmp(known_evp.get(), evp_pkey.get())) {
            LOG(INFO) << "Matched auth_key=" << public_key;
            verified = true;
        } else {
            LOG(INFO) << "auth_key doesn't match [" << public_key << "]";
        }
        RSA_free(key);
        if (verified) {
            *auth_key = public_key;
            authorized = true;
            return false;
        }

        return true;
    });

    return authorized ? 1 : 0;
#endif
}

void adbd_auth_tls_handshake(atransport* t) {
    if (rsa_pkey == nullptr) {
        // Generate a random RSA key to feed into the X509 certificate
        auto rsa_2048 = CreateRSA2048Key();
        CHECK(rsa_2048.has_value());
        rsa_pkey = EVP_PKEY_get1_RSA(rsa_2048->GetEvpPkey());
        CHECK(rsa_pkey);
    }

    std::thread([t]() {
        std::string auth_key;
        if (t->connection()->DoTlsHandshake(rsa_pkey, &auth_key)) {
            LOG(INFO) << "auth_key=" << auth_key;
            if (t->IsTcpDevice()) {
                t->auth_key = auth_key;
                adbd_wifi_secure_connect(t);
            } else {
                adbd_auth_verified(t);
                adbd_notify_framework_connected_key(t);
            }
        } else {
            // Only allow one attempt at the handshake.
            t->Kick();
        }
    }).detach();
}
```

### packages/modules/adb/daemon/main.ccp
```
/*
 * Copyright (C) 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define TRACE_TAG ADB

#include "sysdeps.h"

#if defined(__BIONIC__)
#include <android/fdsan.h>
#endif

#include <errno.h>
#include <getopt.h>
#include <malloc.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/capability.h>
#include <sys/prctl.h>

#include <memory>
#include <vector>

#include <android-base/logging.h>
#include <android-base/macros.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>

#if defined(__ANDROID__)
#include <libminijail.h>
#include <log/log_properties.h>
#include <scoped_minijail.h>

#include <private/android_filesystem_config.h>
#include "selinux/android.h"
#endif

#include "adb.h"
#include "adb_auth.h"
#include "adb_listeners.h"
#include "adb_utils.h"
#include "adb_wifi.h"
#include "socket_spec.h"
#include "transport.h"

#include "daemon/mdns.h"
#include "daemon/watchdog.h"

#if defined(__ANDROID__)
static const char* root_seclabel = nullptr;

static bool should_drop_privileges() {
    // The properties that affect `adb root` and `adb unroot` are ro.secure and
    // ro.debuggable. In this context the names don't make the expected behavior
    // particularly obvious.
    //
    // ro.debuggable:
    //   Allowed to become root, but not necessarily the default. Set to 1 on
    //   eng and userdebug builds.
    //
    // ro.secure:
    //   Drop privileges by default. Set to 1 on userdebug and user builds.
    bool ro_secure = android::base::GetBoolProperty("ro.secure", true);
    bool ro_debuggable = __android_log_is_debuggable();

    // Drop privileges if ro.secure is set...
    bool drop = ro_secure;

    // ... except "adb root" lets you keep privileges in a debuggable build.
    std::string prop = android::base::GetProperty("service.adb.root", "");
    bool adb_root = (prop == "1");
    bool adb_unroot = (prop == "0");
    if (ro_debuggable && adb_root) {
        drop = false;
    }
    // ... and "adb unroot" lets you explicitly drop privileges.
    if (adb_unroot) {
        drop = true;
    }

    return drop;
}

static void drop_privileges(int server_port) {
    ScopedMinijail jail(minijail_new());

    // Add extra groups:
    // AID_ADB to access the USB driver
    // AID_LOG to read system logs (adb logcat)
    // AID_INPUT to diagnose input issues (getevent)
    // AID_INET to diagnose network issues (ping)
    // AID_NET_BT and AID_NET_BT_ADMIN to diagnose bluetooth (hcidump)
    // AID_SDCARD_R to allow reading from the SD card
    // AID_SDCARD_RW to allow writing to the SD card
    // AID_NET_BW_STATS to read out qtaguid statistics
    // AID_READPROC for reading /proc entries across UID boundaries
    // AID_UHID for using 'hid' command to read/write to /dev/uhid
    // AID_EXT_DATA_RW for writing to /sdcard/Android/data (devices without sdcardfs)
    // AID_EXT_OBB_RW for writing to /sdcard/Android/obb (devices without sdcardfs)
    // AID_READTRACEFS for reading tracefs entries
    gid_t groups[] = {AID_ADB,          AID_LOG,          AID_INPUT,    AID_INET,
                      AID_NET_BT,       AID_NET_BT_ADMIN, AID_SDCARD_R, AID_SDCARD_RW,
                      AID_NET_BW_STATS, AID_READPROC,     AID_UHID,     AID_EXT_DATA_RW,
                      AID_EXT_OBB_RW,   AID_READTRACEFS};
    minijail_set_supplementary_gids(jail.get(), arraysize(groups), groups);

    // Don't listen on a port (default 5037) if running in secure mode.
    // Don't run as root if running in secure mode.
    if (should_drop_privileges()) {
        const bool should_drop_caps = !__android_log_is_debuggable();

        if (should_drop_caps) {
            minijail_use_caps(jail.get(), CAP_TO_MASK(CAP_SETUID) | CAP_TO_MASK(CAP_SETGID));
        }

        minijail_change_gid(jail.get(), AID_SHELL);
        minijail_change_uid(jail.get(), AID_SHELL);
        // minijail_enter() will abort if any priv-dropping step fails.
        minijail_enter(jail.get());

        // Whenever ambient capabilities are being used, minijail cannot
        // simultaneously drop the bounding capability set to just
        // CAP_SETUID|CAP_SETGID while clearing the inheritable, effective,
        // and permitted sets. So we need to do that in two steps.
        using ScopedCaps =
            std::unique_ptr<std::remove_pointer<cap_t>::type, std::function<void(cap_t)>>;
        ScopedCaps caps(cap_get_proc(), &cap_free);
        if (cap_clear_flag(caps.get(), CAP_INHERITABLE) == -1) {
            PLOG(FATAL) << "cap_clear_flag(INHERITABLE) failed";
        }
        if (cap_clear_flag(caps.get(), CAP_EFFECTIVE) == -1) {
            PLOG(FATAL) << "cap_clear_flag(PEMITTED) failed";
        }
        if (cap_clear_flag(caps.get(), CAP_PERMITTED) == -1) {
            PLOG(FATAL) << "cap_clear_flag(PEMITTED) failed";
        }
        if (cap_set_proc(caps.get()) != 0) {
            PLOG(FATAL) << "cap_set_proc() failed";
        }

        D("Local port disabled");
    } else {
        // minijail_enter() will abort if any priv-dropping step fails.
        minijail_enter(jail.get());

        if (root_seclabel != nullptr) {
            if (selinux_android_setcon(root_seclabel) < 0) {
                LOG(FATAL) << "Could not set SELinux context";
            }
        }
    }
}
#endif

static void setup_adb(const std::vector<std::string>& addrs) {
#if defined(__ANDROID__)
    // Get the first valid port from addrs and setup mDNS.
    int port = -1;
    std::string error;
    for (const auto& addr : addrs) {
        port = get_host_socket_spec_port(addr, &error);
        if (port != -1) {
            break;
        }
    }
    if (port == -1) {
        port = DEFAULT_ADB_LOCAL_TRANSPORT_PORT;
    }
    LOG(INFO) << "Setup mdns on port= " << port;
    setup_mdns(port);
#endif
    for (const auto& addr : addrs) {
        LOG(INFO) << "adbd listening on " << addr;
        local_init(addr);
    }
}

int adbd_main(int server_port) {
    umask(0);

    signal(SIGPIPE, SIG_IGN);

#if defined(__BIONIC__)
    auto fdsan_level = android_fdsan_get_error_level();
    if (fdsan_level == ANDROID_FDSAN_ERROR_LEVEL_DISABLED) {
        android_fdsan_set_error_level(ANDROID_FDSAN_ERROR_LEVEL_WARN_ONCE);
    }
#endif

    init_transport_registration();

    // We need to call this even if auth isn't enabled because the file
    // descriptor will always be open.
    adbd_cloexec_auth_socket();

#if defined(__ANDROID__)
    // If we're on userdebug/eng or the device is unlocked, permit no-authentication.
    bool device_unlocked = "orange" == android::base::GetProperty("ro.boot.verifiedbootstate", "");
    if (__android_log_is_debuggable() || device_unlocked) {
        // Disabled to allow auto-connect without RSA authentication
        auth_required = false;
#if defined(__ANDROID_RECOVERY__)
        auth_required = false;
#endif
    }
#endif

    // Our external storage path may be different than apps, since
    // we aren't able to bind mount after dropping root.
    const char* adb_external_storage = getenv("ADB_EXTERNAL_STORAGE");
    if (adb_external_storage != nullptr) {
        setenv("EXTERNAL_STORAGE", adb_external_storage, 1);
    } else {
        D("Warning: ADB_EXTERNAL_STORAGE is not set.  Leaving EXTERNAL_STORAGE"
          " unchanged.\n");
    }

#if defined(__ANDROID__)
    drop_privileges(server_port);
#endif

#if defined(__ANDROID__)
    // A thread gets spawned as a side-effect of initializing the watchdog, so it needs to happen
    // after we drop privileges.
    watchdog::Initialize();
#endif

    // adbd_auth_init will spawn a thread, so we need to defer it until after selinux transitions.
    adbd_auth_init();

    bool is_usb = false;

#if defined(__ANDROID__)
    if (access(USB_FFS_ADB_EP0, F_OK) == 0) {
        // Listen on USB.
        usb_init();
        is_usb = true;
    }
#endif

    // If one of these properties is set, also listen on that port.
    // If one of the properties isn't set and we couldn't listen on usb, listen
    // on the default port.
    std::vector<std::string> addrs;
    std::string prop_addr = android::base::GetProperty("service.adb.listen_addrs", "");
    if (prop_addr.empty()) {
        std::string prop_port = android::base::GetProperty("service.adb.tcp.port", "");
        if (prop_port.empty()) {
            prop_port = android::base::GetProperty("persist.adb.tcp.port", "");
        }

#if !defined(__ANDROID__)
        if (prop_port.empty() && getenv("ADBD_PORT")) {
            prop_port = getenv("ADBD_PORT");
        }
#endif

        int port;
        if (sscanf(prop_port.c_str(), "%d", &port) == 1 && port > 0) {
            D("using tcp port=%d", port);
            // Listen on TCP and VSOCK port specified by service.adb.tcp.port property.
            addrs.push_back(android::base::StringPrintf("tcp:%d", port));
            addrs.push_back(android::base::StringPrintf("vsock:%d", port));
            setup_adb(addrs);
        } else if (!is_usb) {
            // Listen on default port.
            addrs.push_back(
                    android::base::StringPrintf("tcp:%d", DEFAULT_ADB_LOCAL_TRANSPORT_PORT));
            addrs.push_back(
                    android::base::StringPrintf("vsock:%d", DEFAULT_ADB_LOCAL_TRANSPORT_PORT));
            setup_adb(addrs);
        }
    } else {
        addrs = android::base::Split(prop_addr, ",");
        setup_adb(addrs);
    }

    LOG(INFO) << "adbd started";

    D("adbd_main(): pre init_jdwp()");
    init_jdwp();
    D("adbd_main(): post init_jdwp()");

    D("Event loop starting");
    fdevent_loop();

    return 0;
}

int main(int argc, char** argv) {
#if defined(__BIONIC__)
    // Set M_DECAY_TIME so that our allocations aren't immediately purged on free.
    mallopt(M_DECAY_TIME, 1);
#endif

    while (true) {
        static struct option opts[] = {
                {"root_seclabel", required_argument, nullptr, 's'},
                {"device_banner", required_argument, nullptr, 'b'},
                {"version", no_argument, nullptr, 'v'},
                {"logpostfsdata", no_argument, nullptr, 'l'},
        };

        int option_index = 0;
        int c = getopt_long(argc, argv, "", opts, &option_index);
        if (c == -1) {
            break;
        }

        switch (c) {
#if defined(__ANDROID__)
            case 's':
                root_seclabel = optarg;
                break;
#endif
            case 'b':
                adb_device_banner = optarg;
                break;
            case 'v':
                printf("Android Debug Bridge Daemon version %d.%d.%d\n", ADB_VERSION_MAJOR,
                       ADB_VERSION_MINOR, ADB_SERVER_VERSION);
                return 0;
            case 'l':
                LOG(ERROR) << "post-fs-data triggered";
                return 0;
            default:
                // getopt already prints "adbd: invalid option -- %c" for us.
                return 1;
        }
    }

    close_stdin();

    adb_trace_init(argv);

    D("Handling main()");
    return adbd_main(DEFAULT_ADB_PORT);
}
