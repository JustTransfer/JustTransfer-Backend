// @generated automatically by Diesel CLI.

diesel::table! {
    key_pairs (id) {
        id -> Uuid,
        owner_id -> Uuid,
        enc_public_key -> Bytea,
        enc_nonce_private_key -> Bytea,
        enc_cipher_private_key -> Bytea,
        sign_public_key -> Bytea,
        sign_nonce_private_key -> Bytea,
        sign_cipher_private_key -> Bytea,
        is_active -> Bool,
        created_at -> Timestamptz,
        revoked_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    link_transfers (id) {
        id -> Uuid,
        upload_id -> Text,
        password_file -> Bytea,
        server_login -> Nullable<Bytea>,
        auth_key -> Uuid,
        c_enc_key -> Bytea,
        nonce_enc_key -> Bytea,
        c_mac_key -> Bytea,
        nonce_mac_key -> Bytea,
        cfilename -> Bytea,
        nonce_filename -> Bytea,
        file_id -> Uuid,
        max_downloads -> Int8,
        lifetime -> Int8,
        creation_time -> Timestamptz,
        hash_file -> Nullable<Bytea>,
        mac -> Nullable<Bytea>,
        number_downloads -> Int8,
        file_size -> Int8,
        chunk_size -> Int8,
        is_signed -> Bool,
        sender_key_id -> Nullable<Uuid>,
        signature_metadata -> Nullable<Bytea>,
        signature -> Nullable<Bytea>,
    }
}

diesel::table! {
    opaque_settings (id) {
        id -> Int4,
        settings -> Bytea,
    }
}

diesel::table! {
    reset_tokens (id) {
        id -> Uuid,
        account_id -> Uuid,
        token -> Uuid,
        expires_at -> Timestamptz,
    }
}

diesel::table! {
    saved_transfers (id) {
        id -> Uuid,
        owner_id -> Uuid,
        nonce_transfer_id -> Bytea,
        enc_transfer_id -> Bytea,
        nonce_password -> Bytea,
        enc_password -> Bytea,
        nonce_auth_key -> Nullable<Bytea>,
        enc_auth_key -> Nullable<Bytea>,
    }
}

diesel::table! {
    users (id) {
        id -> Uuid,
        email -> Text,
        password_file -> Bytea,
        server_login -> Nullable<Bytea>,
        role -> Text,
        number_transfers -> Int8,
        created_at -> Timestamptz,
        registration_token -> Uuid,
        email_verified -> Bool,
        payrexx_subscription_id -> Nullable<Int8>,
    }
}

diesel::joinable!(key_pairs -> users (owner_id));
diesel::joinable!(link_transfers -> key_pairs (sender_key_id));
diesel::joinable!(reset_tokens -> users (account_id));
diesel::joinable!(saved_transfers -> users (owner_id));

diesel::allow_tables_to_appear_in_same_query!(
    key_pairs,
    link_transfers,
    opaque_settings,
    reset_tokens,
    saved_transfers,
    users,
);
