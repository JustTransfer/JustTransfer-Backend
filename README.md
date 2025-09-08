# JujuTransfer


| Sender    | Receiver  | Method                                       |
|-----------|-----------|----------------------------------------------|
| anonymous | anonymous | Passphrase to get the symmetric key          |
| login     | anonymous | Passphrase to get the symmetric key          |
| anonymous | login     | Use the public key of the receiver -> remove |
| login     | login     | Use the public key of the receiver           |


## Price plan
- Free, limit in size (10 GB, 100 files, max 15 days)
- Premium, no size limit, no time limit, etc.

## TODO
- Support large files (not in memory)
- Files in a bucket S3
- Validate password strength
- Validate username (email format and code transmitted by email)
- Anonymous mode
- Add a counter to max number of anonymous transfers
- Add a counter to max number of transfers
- OPAQUE save server state
- Messages disappearing in the DB -> normal if user is deleted
- Use TLD for the signatures (not just concatenate)
- Add a key rotation option
- Put public key of signature in the message
- Validate public key retrieved from the server (Authenticated Data in AEAD)
- Add a delete account option

## Install Diesel
```bash
setx PQ_LIB_DIR "C:\Program Files\PostgreSQL\17\lib"
cargo install diesel_cli --no-default-features --features postgres
```

Set Path variable `C:\Program Files\PostgreSQL\17\bin`.

## Run Diesel

```bash
diesel setup
diesel migration generate initial_migration # Fulfill the up.sql and down.sql files
diesel migration run

diesel print-schema > src/schema.rs # Generate schema.rs from the database
```