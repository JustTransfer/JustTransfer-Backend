// @generated automatically by Diesel CLI.

diesel::table! {
    anonymousmessages (id) {
        id -> Uuid,
        upload_id -> Text,
        password_file -> Bytea,
        server_login -> Nullable<Bytea>,
        cfilename -> Bytea,
        nonce_filename -> Bytea,
        file_id -> Uuid,
        header -> Bytea,
        max_downloads -> Int4,
        lifetime -> Int4,
        creation_time -> Timestamptz,
        number_downloads -> Int4,
        file_size -> Int8,
        chunk_size -> Int8,
    }
}

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
    messages (id) {
        id -> Uuid,
        upload_id -> Text,
        sender_key_id -> Uuid,
        receiver_key_id -> Uuid,
        cfilename -> Bytea,
        nonce_filename -> Bytea,
        file_id -> Uuid,
        nonce_message -> Bytea,
        max_downloads -> Int4,
        lifetime -> Int4,
        creation_time -> Timestamptz,
        signature -> Nullable<Bytea>,
        number_downloads -> Int4,
        file_size -> Int8,
        chunk_size -> Int8,
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
    users (id) {
        id -> Uuid,
        username -> Text,
        email -> Text,
        password_file -> Bytea,
        server_login -> Nullable<Bytea>,
        role -> Text,
        number_transfers -> Int4,
        created_at -> Timestamptz,
        registration_token -> Uuid,
        email_verified -> Bool,
    }
}

diesel::joinable!(key_pairs -> users (owner_id));
diesel::joinable!(reset_tokens -> users (account_id));

diesel::allow_tables_to_appear_in_same_query!(
    anonymousmessages,
    key_pairs,
    messages,
    opaque_settings,
    reset_tokens,
    users,
);
