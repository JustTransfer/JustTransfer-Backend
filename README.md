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

## TODO Backend
- Fix HTTP return codes
- Validate email (email format and code transmitted by email)
- Add a username which is unique in the app (in addition to email)
- Anonymous mode
- Add a counter to max number of anonymous transfers (avoid server overload)
- Add a counter to max number of transfers (avoid server overload)
- Put public key of signature in the message
- Add a key rotation option
- Add a delete account option
- Login endpoint to have a supervisor

- Files in a bucket S3

## TODO Frontend
- Validate password strength
- Support large files (not in memory)
- Support drag and drop
- Make account page (key rotation, delete account, etc.)
- Make anonymous transfer page (create transfer and receive transfer)
- Use TLD for the signatures (not just concatenate)
- Validate public key retrieved from the server (Authenticated Data in AEAD)

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