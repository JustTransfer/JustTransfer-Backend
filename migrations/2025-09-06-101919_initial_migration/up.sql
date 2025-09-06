-- Table users
CREATE TABLE users
(
    id                      SERIAL PRIMARY KEY,
    username                TEXT  NOT NULL UNIQUE,
    password_file           BYTEA NOT NULL,

    public_key_enc          BYTEA NOT NULL,
    nonce_enc               BYTEA NOT NULL,
    cipher_private_key_enc  BYTEA NOT NULL,

    public_key_sign         BYTEA NOT NULL,
    nonce_sign              BYTEA NOT NULL,
    cipher_private_key_sign BYTEA NOT NULL
);

-- Table messages
CREATE TABLE messages
(
    id             SERIAL PRIMARY KEY,
    sender_id      INT   NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    receiver_id    INT   NOT NULL REFERENCES users (id) ON DELETE CASCADE,

    filename       BYTEA NOT NULL,
    nonce_filename BYTEA NOT NULL,
    message        BYTEA NOT NULL,
    nonce_message  BYTEA NOT NULL,
    signature      BYTEA NOT NULL
);
