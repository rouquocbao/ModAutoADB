### packages/modules/adb/daemon/auth.cpp
sửa:
```
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
```
Thành:
```
void adbd_auth_confirm_key(atransport* t) {
    LOG(INFO) << "Internal ROM: Auto-authorizing client key...";
    
    // Gọi thẳng hàm thông báo rằng key này đã được xác thực thành công
    adbd_auth_verified(t);
    
    /* Xóa hoặc comment toàn bộ logic cũ để không hiện Popup lên màn hình nữa
       t->AddDisconnect(&adb_disconnect);
       if (adbd_auth_prompt_user_with_id) { ... } 
    */
}
```
