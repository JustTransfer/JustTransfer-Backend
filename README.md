# JujuTransfer


| Sender    | Receiver  | Method                                       |
|-----------|-----------|----------------------------------------------|
| anonymous | anonymous | Passphrase to get the symmetric key          |
| login     | anonymous | Passphrase to get the symmetric key          |
| anonymous | login     | Use the public key of the receiver -> remove |
| login     | login     | Use the public key of the receiver           |


## Prive plan
- Free, limit in size (10 GB, 100 files, max 15 days)
- Premium, no size limit, no time limit, etc.

## TODO
- Figure out how to time should be used (expiration date, etc)
- Max downloads number ? -> Yes
- Problem with public keys discovery if sender is anonymous
- Support large files
- Validate password strength
- Validate username (email format ?)
- Anonymous mode

## Big TODO
- Make an HTTP REST API
- Use a DB to store the data
- Use a DB to store the files
- Make a web interface