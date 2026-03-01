# JustTransfer


| Sender    | Receiver  | Method                                       |
|-----------|-----------|----------------------------------------------|
| anonymous | anonymous | Passphrase to get the symmetric key          |
| login     | anonymous | Passphrase to get the symmetric key          |
| anonymous | login     | Use the public key of the receiver -> remove |
| login     | login     | Use the public key of the receiver           |


## Price plan
- Free, limit in size (10 GB, 100 files, max 15 days, max downloads)
- Premium, no size limit, no time limit, etc.

## Features
- TODO

## Install Diesel

```bash
# On Windows
setx PQ_LIB_DIR "C:\Program Files\PostgreSQL\17\lib"
cargo install diesel_cli --no-default-features --features postgres

# On linux
sudo apt install libpq-dev
```

Set Path variable `C:\Program Files\PostgreSQL\17\bin`.

## Run Diesel

```bash
# Launch PostgreSQL server
docker compose up -d postgres

diesel setup
diesel migration generate initial_migration # Fulfill the up.sql and down.sql files from the database
diesel migration run

diesel print-schema > src/schema.rs # Generate schema.rs from the database
```

