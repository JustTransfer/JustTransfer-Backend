// @generated automatically by Diesel CLI.

diesel::table! {
    anonymousmessages (id) {
        id -> Uuid,
        password_file -> Bytea,
        filename -> Bytea,
        nonce_filename -> Bytea,
        message_id -> Uuid,
        nonce_message -> Bytea,
        max_downloads -> Int4,
        lifetime -> Int4,
        creation_time -> Timestamptz,
        number_downloads -> Int4,
    }
}

diesel::table! {
    messages (id) {
        id -> Int4,
        sender_id -> Int4,
        receiver_id -> Int4,
        filename -> Bytea,
        nonce_filename -> Bytea,
        message_id -> Uuid,
        nonce_message -> Bytea,
        max_downloads -> Int4,
        lifetime -> Int4,
        creation_time -> Timestamptz,
        signature -> Bytea,
        number_downloads -> Int4,
    }
}

diesel::table! {
    opaque_settings (id) {
        id -> Int4,
        settings -> Bytea,
    }
}

diesel::table! {
    roles (role) {
        role -> Text,
    }
}

diesel::table! {
    users (id) {
        id -> Int4,
        username -> Text,
        password_file -> Bytea,
        role -> Text,
        public_key_enc -> Bytea,
        nonce_enc -> Bytea,
        cipher_private_key_enc -> Bytea,
        public_key_sign -> Bytea,
        nonce_sign -> Bytea,
        cipher_private_key_sign -> Bytea,
    }
}

diesel::joinable!(users -> roles (role));

diesel::allow_tables_to_appear_in_same_query!(
    anonymousmessages,
    messages,
    opaque_settings,
    roles,
    users,
);
