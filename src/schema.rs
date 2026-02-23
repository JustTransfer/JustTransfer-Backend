// @generated automatically by Diesel CLI.

diesel::table! {
    anonymousmessages (id) {
        id -> Uuid,
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
    messages (id) {
        id -> Uuid,
        sender_id -> Uuid,
        receiver_id -> Uuid,
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
    users (id) {
        id -> Uuid,
        username -> Text,
        email -> Text,
        password_file -> Bytea,
        server_login -> Nullable<Bytea>,
        role -> Text,
        number_transfers -> Int4,
        public_key_enc -> Bytea,
        nonce_enc -> Bytea,
        cipher_private_key_enc -> Bytea,
        public_key_sign -> Bytea,
        nonce_sign -> Bytea,
        cipher_private_key_sign -> Bytea,
    }
}

diesel::allow_tables_to_appear_in_same_query!(anonymousmessages, messages, opaque_settings, users,);
