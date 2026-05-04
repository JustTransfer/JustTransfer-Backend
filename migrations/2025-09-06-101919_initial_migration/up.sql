-- Table OPAQUE settings
CREATE TABLE opaque_settings
(
    id                       SERIAL     PRIMARY KEY,
    settings                 BYTEA      NOT NULL
);

-- Table users
CREATE TABLE users
(
    id                      UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    username                TEXT        NOT NULL UNIQUE,
    email                   TEXT        NOT NULL UNIQUE,
    password_file           BYTEA       NOT NULL,
    server_login            BYTEA,
    role                    TEXT        NOT NULL CHECK (role IN ('user', 'premium', 'admin', 'anonymous')),
    number_transfers        BIGINT      NOT NULL DEFAULT 0,

    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),

    registration_token      UUID        NOT NULL UNIQUE,
    email_verified          BOOLEAN     NOT NULL DEFAULT false
);

-- Table key_pairs
CREATE TABLE key_pairs
(
    id                      UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id                UUID        NOT NULL REFERENCES users(id),

    enc_public_key          BYTEA       NOT NULL,
    enc_nonce_private_key   BYTEA       NOT NULL,
    enc_cipher_private_key  BYTEA       NOT NULL,

    sign_public_key         BYTEA       NOT NULL,
    sign_nonce_private_key  BYTEA       NOT NULL,
    sign_cipher_private_key BYTEA       NOT NULL,

    is_active               BOOLEAN     NOT NULL DEFAULT true,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at              TIMESTAMPTZ
);

-- Table reset_tokens
CREATE TABLE reset_tokens
(
    id                      UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id              UUID        NOT NULL UNIQUE REFERENCES users(id),
    token                   UUID        NOT NULL UNIQUE,
    expires_at              TIMESTAMPTZ NOT NULL
);

-- Table messages
CREATE TABLE messages
(
    id                      UUID        PRIMARY KEY DEFAULT gen_random_uuid(),

    upload_id               TEXT        NOT NULL,

    sender_key_id           UUID        NOT NULL REFERENCES key_pairs (id),
    receiver_key_id         UUID        NOT NULL REFERENCES key_pairs (id),

    kem_ciphertext_filename BYTEA       NOT NULL,
    cfilename               BYTEA       NOT NULL,
    nonce_filename          BYTEA       NOT NULL,
    file_id                 UUID        NOT NULL UNIQUE,
    kem_ciphertext_file     BYTEA       NOT NULL,
    max_downloads           BIGINT      NOT NULL,
    lifetime                BIGINT      NOT NULL,
    creation_time           TIMESTAMPTZ NOT NULL,
    signature_metadata      BYTEA,
    number_downloads        BIGINT      DEFAULT 0 NOT NULL,
    file_size               BIGINT      NOT NULL,
    chunk_size              BIGINT      NOT NULL,
    signature               BYTEA
);

-- Table Anonymous messages
CREATE TABLE anonymousMessages
(
    id                      UUID        PRIMARY KEY,

    upload_id               TEXT        NOT NULL,

    password_file           BYTEA       NOT NULL,
    server_login            BYTEA,

    cfilename               BYTEA       NOT NULL,
    nonce_filename          BYTEA       NOT NULL,
    file_id                 UUID        NOT NULL UNIQUE,
    max_downloads           BIGINT      NOT NULL,
    lifetime                BIGINT      NOT NULL,
    creation_time           TIMESTAMPTZ NOT NULL,
    mac                     BYTEA,
    number_downloads        BIGINT DEFAULT 0 NOT NULL,
    file_size               BIGINT        NOT NULL,
    chunk_size              BIGINT        NOT NULL
);