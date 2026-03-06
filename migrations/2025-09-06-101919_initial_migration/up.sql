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
    number_transfers        INT         NOT NULL DEFAULT 0,

    created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
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

-- Table messages
CREATE TABLE messages
(
    id                      UUID        PRIMARY KEY DEFAULT gen_random_uuid(),

    sender_key_id           UUID        NOT NULL REFERENCES key_pairs (id),
    receiver_key_id         UUID        NOT NULL REFERENCES key_pairs (id),

    cfilename               BYTEA       NOT NULL,
    nonce_filename          BYTEA       NOT NULL,
    file_id                 UUID        NOT NULL UNIQUE,
    nonce_message           BYTEA       NOT NULL,
    max_downloads           INT         NOT NULL,
    lifetime                INT         NOT NULL,
    creation_time           TIMESTAMPTZ NOT NULL,
    signature               BYTEA,
    number_downloads        INT DEFAULT 0 NOT NULL,
    file_size               BIGINT        NOT NULL,
    chunk_size              BIGINT        NOT NULL
);

-- Table Anonymous messages
CREATE TABLE anonymousMessages
(
    id                      UUID        PRIMARY KEY,

    password_file           BYTEA       NOT NULL,
    server_login            BYTEA,

    cfilename               BYTEA       NOT NULL,
    nonce_filename          BYTEA       NOT NULL,
    file_id                 UUID        NOT NULL UNIQUE,
    header                  BYTEA       NOT NULL,
    max_downloads           INT         NOT NULL,
    lifetime                INT         NOT NULL,
    creation_time           TIMESTAMPTZ NOT NULL,
    number_downloads        INT DEFAULT 0 NOT NULL,
    file_size               BIGINT        NOT NULL,
    chunk_size              BIGINT        NOT NULL
);