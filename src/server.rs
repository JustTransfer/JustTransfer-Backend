use std::time::{SystemTime, Instant};
use libsodium_sys::*;
use num_bigint::BigUint;

use crate::database::{Database, Message};
use crate::consts::*;
use rand::rngs::OsRng;
use opaque_ke::*;
use std::default::Default;
use std::{io, result};
use argon2::Argon2;

#[allow(dead_code)]
pub struct DefaultCipherSuite;
impl CipherSuite for DefaultCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;
    type Ksf = Argon2<'static>;
}

#[derive(Clone)]
pub struct Server {
    pub(crate) db: Database,
    server_opaque: ServerSetup<DefaultCipherSuite>,
}

impl Server {
    pub fn new() -> Self {
        let mut rng = OsRng;
        let server_setup = ServerSetup::<DefaultCipherSuite>::new(&mut rng);

        Server {
            db: Database::new(),
            server_opaque: server_setup,
        }
    }

    pub fn server_registration_start(&mut self, username: &str,client_registration_start_result: RegistrationRequest<DefaultCipherSuite>) -> Result<RegistrationResponse<DefaultCipherSuite>, Box<dyn std::error::Error>> {
        let server_registration_start_result = ServerRegistration::<DefaultCipherSuite>::start(
            &self.server_opaque,
            client_registration_start_result,
            username.as_bytes(),
        ).map_err(|e| e.to_string())?;

        Ok(server_registration_start_result.message)
    }

    pub fn server_registration_finish(&mut self, client_registration_finish_result:  RegistrationUpload<DefaultCipherSuite>,
                                      username: &str,
                                      cpriv_enc: Vec<u8>,
                                      nonce_priv_enc: [u8; SYM_LEN_NONCE],
                                      pub_enc: [u8; ENC_KEY_LEN_PUB],
                                      cpriv_sign: Vec<u8>,
                                      nonce_priv_sign: [u8; SYM_LEN_NONCE],
                                      pub_sign: [u8; SIGN_KEY_LEN_PUB]
    ) -> Result<(), Box<dyn std::error::Error>> {
        let password_file = ServerRegistration::<DefaultCipherSuite>::finish(
            client_registration_finish_result,
        );

        let password_file_bytes = password_file.serialize();

        if self.db.get_user(&username).is_some() {
            // Error if the user already exists
            return Err(Box::new(io::Error::new(io::ErrorKind::Other, "User already exists")));
        } else {
            self.db.create_user(
                username.parse().unwrap(),
                password_file_bytes,
                cpriv_enc,
                nonce_priv_enc,
                pub_enc,
                cpriv_sign,
                nonce_priv_sign,
                pub_sign,
            )?;
        }

        Ok(())
    }

    pub fn server_registration_finish_update(&mut self, client_registration_finish_result: RegistrationUpload<DefaultCipherSuite>,
                                             username: &str,
                                             mac: [u8; MAC_LEN],
                                             cpriv1: Vec<u8>,
                                             nonce1: [u8; SYM_LEN_NONCE],
                                             pub1: [u8; ENC_KEY_LEN_PUB],
                                             cpriv2: Vec<u8>,
                                             nonce2: [u8; SYM_LEN_NONCE],
                                             pub2: [u8; SIGN_KEY_LEN_PUB]
    ) -> Result<(), Box<dyn std::error::Error>> {
        let password_file = ServerRegistration::<DefaultCipherSuite>::finish(
            client_registration_finish_result,
        );

        let password_file_bytes = password_file.serialize();

        // Check if the user is connected using mac
        self.check_mac(&*username, mac).ok();

        if self.db.get_user(&username).is_some() {
            self.db.modify_user(
                username.parse().unwrap(), password_file_bytes, cpriv1, nonce1, pub1, cpriv2, nonce2, pub2,
            )?;
        }

        Ok(())
    }

    pub fn server_login_start(&mut self, username: &str, client_login_start_result:  CredentialRequest<DefaultCipherSuite>) -> Result<(CredentialResponse<DefaultCipherSuite>, ServerLogin<DefaultCipherSuite>), Box<dyn std::error::Error>> {
        let password_file_bytes = self.db.get_user(&username).ok_or("User not found")?.password_file.clone();

        let password_file = ServerRegistration::<DefaultCipherSuite>::deserialize(&password_file_bytes).map_err(|e| e.to_string())?;

        let mut server_rng = OsRng;
        let server_login_start_result = ServerLogin::start(
            &mut server_rng,
            &self.server_opaque,
            Some(password_file),
            client_login_start_result,
            username.as_bytes(),
            ServerLoginStartParameters::default(),
        ).map_err(|e| e.to_string())?;

        Ok((server_login_start_result.message, server_login_start_result.state))
    }

    pub fn server_login_finish(&mut self, username: &str, server_login_start_result: ServerLogin<DefaultCipherSuite>, client_login_finish_result:  CredentialFinalization<DefaultCipherSuite>) -> Result<([u8; ENC_KEY_LEN_PUB], Vec<u8>, [u8; SYM_LEN_NONCE], [u8; SIGN_KEY_LEN_PUB], Vec<u8>, [u8; SYM_LEN_NONCE]), Box<dyn std::error::Error>> {

        let server_login_finish_result = server_login_start_result.finish(
            client_login_finish_result,
        ).map_err(|e| e.to_string())?;

        // Key to check if the user is connected
        let key_communication = server_login_finish_result.session_key.clone();

        if key_communication.len() < MAC_LEN {
            return Err(Box::new(io::Error::new(io::ErrorKind::Other, "Error in key generation")));
        }

        self.db.connect_user(username.to_string(), key_communication)?;

        let user = self.db.get_user(&*username).unwrap();

        Ok((
            user.asysm_key_encryption.public_key.clone(),
            user.asysm_key_encryption.cipher_private_key.clone(),
            user.asysm_key_encryption.nonce.clone(),
            user.asysm_key_signing.public_key.clone(),
            user.asysm_key_signing.cipher_private_key.clone(),
            user.asysm_key_signing.nonce.clone(),
        ))
    }

    fn check_mac(& self, username: &str, mac: [u8; MAC_LEN]) -> Result<(), Box<dyn std::error::Error>> {

        let result = unsafe {
            crypto_auth_verify(
                mac.as_ptr(),
                username.as_bytes().as_ptr(),
                username.as_bytes().len() as u64,
                self.db.get_connected_user(username).as_ptr(),
            )
        };

        if result != 0 {
            return Err(Box::new(io::Error::new(io::ErrorKind::Other, "MAC invalid")));
        }

        Ok(())
    }

    pub fn logout(&mut self, username: &str, mac: [u8; MAC_LEN]) -> Result<(), Box<dyn std::error::Error>> {
        // Check if the user is connected using mac
        self.check_mac(username, mac)?;

        self.db.disconnect_user(username)?;

        Ok(())
    }

    pub fn get_pub_key_enc(& self, username: &str, mac: [u8; MAC_LEN], username_pub_key: &str) -> Option<[u8; ENC_KEY_LEN_PUB]> {
        // Check if the user is connected using mac
        self.check_mac(username, mac).ok()?;

        self.db.get_user(username_pub_key).map(|u| u.asysm_key_encryption.public_key.clone())
    }

    pub fn get_pub_key_sign(& self, username: &str, mac: [u8; MAC_LEN], username_pub_key: &str) -> Option<[u8; SIGN_KEY_LEN_PUB]> {
        // Check if the user is connected using mac
        self.check_mac(username, mac).ok()?;

        self.db.get_user(username_pub_key).map(|u| u.asysm_key_signing.public_key.clone())
    }

    pub fn send_message(&mut self, mac: [u8; MAC_LEN], sender: &str, receiver: &str, filename: Vec<u8>, nonce_filename: [u8; ENC_LEN_NONCE], message: Vec<u8>, nonce_message: [u8; ENC_LEN_NONCE], signature: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
        // Check if the user is connected using mac
        self.check_mac(sender, mac)?;

        self.db.send_message(sender, receiver, filename, nonce_filename, message, nonce_message, signature)?;

        Ok(())
    }

    pub fn get_messages(&mut self, mac: [u8; MAC_LEN], username: &str) -> Result<Vec<Message>, Box<dyn std::error::Error>> {
        // Check if the user is connected
        self.check_mac(username, mac)?;

        let messages = self.db.get_messages(username)?;

        // Make a copy of the messages
        let copied_messages: Vec<Message> = messages.iter().cloned().collect();

        Ok(copied_messages)
    }
}