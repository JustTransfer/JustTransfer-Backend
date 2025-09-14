-- Table OPAQUE settings
CREATE TABLE opaque_settings
(
    id                       SERIAL PRIMARY KEY,
    settings                 BYTEA NOT NULL
);


-- Table roles
CREATE TABLE roles
(
    role                    TEXT PRIMARY KEY
);

-- Fill the roles table with initial data
INSERT INTO roles (role)
VALUES ('user'),
       ('premium_user'),
       ('admin');

-- Table users
CREATE TABLE users
(
    id                      SERIAL PRIMARY KEY,
    username                TEXT  NOT NULL UNIQUE,
    password_file           BYTEA NOT NULL,
    role                    TEXT  NOT NULL REFERENCES roles (role) ON DELETE RESTRICT,

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
    id               SERIAL PRIMARY KEY,
    sender_id        INT           NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    receiver_id      INT           NOT NULL REFERENCES users (id) ON DELETE CASCADE,

    filename         BYTEA         NOT NULL,
    nonce_filename   BYTEA         NOT NULL,
    message_id       UUID          NOT NULL UNIQUE,
    nonce_message    BYTEA         NOT NULL,
    max_downloads    INT           NOT NULL,
    lifetime         INT           NOT NULL,
    creation_time    TIMESTAMPTZ   NOT NULL,
    signature        BYTEA         NOT NULL,
    number_downloads INT DEFAULT 0 NOT NULL
);