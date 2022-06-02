#![no_std]

use aes_gcm::aead::{AeadInPlace, NewAead};
use aes_gcm::{Aes128Gcm, Key, Nonce};
use buffer::Buffer;
use embedded_io::blocking::{Read, Write};
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};

use sha2::Digest;
use sha2::Sha256;
use x25519_dalek::PublicKey;
use x25519_dalek::StaticSecret;

pub mod buffer;

#[derive(Debug)]
pub enum TlsError {
    ReceivedUnexpectedData,
    IoError(),
}

pub struct Session<'a, T>
where
    T: Read + Write,
{
    stream: T,
    servername: &'a str,
    pub secret: StaticSecret,
    pub random: [u8; 32],
    pub server_random: Option<[u8; 32]>,
    pub server_public_key: Option<[u8; 32]>,
    pub client_hello: Option<Buffer<8192>>,
    pub server_hello: Option<Buffer<8192>>,
    pub client_handshake_key: Option<Buffer<128>>,
    pub server_handshake_key: Option<Buffer<128>>,
    pub client_handshake_iv: Option<Buffer<128>>,
    pub server_handshake_iv: Option<Buffer<128>>,
    pub server_handshake: Option<Buffer<8192>>,
    pub handshake_secret: Option<Buffer<128>>,
    pub client_application_key: Option<Buffer<128>>,
    pub server_application_key: Option<Buffer<128>>,
    pub client_application_iv: Option<Buffer<128>>,
    pub server_application_iv: Option<Buffer<128>>,
    pub client_handshake_secret: Option<Buffer<128>>,
    pub records_received: usize,
    pub records_sent: usize,
}

impl<'a, T> Session<'a, T>
where
    T: Read + Write,
{
    pub fn new<RNG>(stream: T, servername: &'a str, rng: &mut RNG) -> Session<'a, T>
    where
        RNG: CryptoRng + RngCore + rand_core::CryptoRng,
    {
        let mut random = [0u8; 32];
        rng.fill_bytes(&mut random);

        let secret = StaticSecret::new(rng);

        Session {
            stream,
            servername,
            secret,
            random,
            server_random: None,
            server_public_key: None,
            client_hello: None,
            server_hello: None,
            client_handshake_key: None,
            server_handshake_key: None,
            client_handshake_iv: None,
            server_handshake_iv: None,
            server_handshake: None,
            handshake_secret: None,
            client_application_key: None,
            server_application_key: None,
            client_application_iv: None,
            server_application_iv: None,
            client_handshake_secret: None,
            records_received: 0,
            records_sent: 0,
        }
    }

    pub fn new_test(
        stream: T,
        servername: &'a str,
        random: [u8; 32],
        key: [u8; 32],
    ) -> Session<'a, T> {
        let secret = StaticSecret::from(key);

        Session {
            stream,
            servername,
            secret,
            random,
            server_random: None,
            server_public_key: None,
            client_hello: None,
            server_hello: None,
            client_handshake_key: None,
            server_handshake_key: None,
            client_handshake_iv: None,
            server_handshake_iv: None,
            server_handshake: None,
            handshake_secret: None,
            client_application_key: None,
            server_application_key: None,
            client_application_iv: None,
            server_application_iv: None,
            client_handshake_secret: None,
            records_received: 0,
            records_sent: 0,
        }
    }

    pub fn connect(&mut self) -> Result<(), TlsError> {
        self.send_client_hello()?;
        self.process_server_hello()
    }

    pub fn test_process_server_hello(&mut self) -> Result<(), TlsError> {
        self.process_server_hello()
    }

    fn process_server_hello(&mut self) -> Result<(), TlsError> {
        let (_, buffer) = self.read_record_to_buffer()?;
        self.process_server_hello_remaining(buffer)
    }

    fn process_server_hello_remaining(&mut self, mut buffer: Buffer<8192>) -> Result<(), TlsError> {
        log::trace!("ServerHello {:02x?}", buffer.slice());

        buffer.read();
        buffer.read();
        buffer.read();
        buffer.read();
        buffer.read();

        // we already skipped over the first 5 bytes
        if buffer.read().unwrap() != 0x02 {
            // handshake header
            return Err(TlsError::ReceivedUnexpectedData);
        }

        if buffer.read().unwrap() != 0x00 {
            return Err(TlsError::ReceivedUnexpectedData);
        }

        let _handshake_len =
            ((buffer.read().unwrap() as usize) << 8usize) | buffer.read().unwrap() as usize;

        if buffer.read().unwrap() != 0x03 {
            return Err(TlsError::ReceivedUnexpectedData);
        }
        if buffer.read().unwrap() != 0x03 {
            return Err(TlsError::ReceivedUnexpectedData);
        }

        let mut server_random = [0u8; 32];
        for i in 0..32 {
            server_random[i] = buffer.read().unwrap();
        }

        log::info!("Server random is {:02x?}", &server_random);
        self.server_public_key = Some(server_random);

        let session_id_len = buffer.read().unwrap();
        log::info!("Session ID len is {}", session_id_len);

        for _ in 0..session_id_len {
            buffer.read().unwrap(); // skip over it
        }

        let cipher_suite_id =
            ((buffer.read().unwrap() as usize) << 8usize) | buffer.read().unwrap() as usize;
        log::info!("Chiper Suite ID is {:x}", cipher_suite_id);

        let compression_method = buffer.read().unwrap();
        log::info!("Compression method is {}", compression_method);

        // continue with extension_length, parse extensions
        let extensions_len =
            ((buffer.read().unwrap() as usize) << 8usize) | buffer.read().unwrap() as usize;
        let mut read_extension_bytes = 0;
        while extensions_len != 0 && read_extension_bytes < extensions_len {
            let extension_id =
                ((buffer.read().unwrap() as usize) << 8usize) | buffer.read().unwrap() as usize;
            let extension_len =
                ((buffer.read().unwrap() as usize) << 8usize) | buffer.read().unwrap() as usize;

            let mut extension_data = Buffer::<128>::new();
            for _ in 0..extension_len {
                extension_data.push_byte(buffer.read().unwrap());
            }

            log::trace!(
                "Read extension ID {:x} with {} bytes of data",
                extension_id,
                extension_len
            );

            match extension_id {
                0x0033 => {
                    log::info!("got the server's public key");
                    extension_data.read().unwrap(); // x25519
                    extension_data.read().unwrap(); // x25519

                    let key_len = ((extension_data.read().unwrap() as usize) << 8usize)
                        | extension_data.read().unwrap() as usize;
                    log::info!("key len is {}", key_len);

                    let mut key = [0u8; 32];
                    key[..].copy_from_slice(extension_data.remaining_slice());
                    self.server_public_key = Some(key);
                }
                _ => {
                    log::info!("Ignoring extension {:x}", extension_id);
                }
            }

            read_extension_bytes += 2 + 2 + extension_len;
        }
        self.server_hello = Some(Buffer::<8192>::new_from_slice(
            buffer.already_consumed_slice(),
        ));

        self.make_handshake_keys();

        // ignore change cipher spec
        let (_, _) = self.read_record_to_buffer()?;

        self.process_server_handshake()
    }

    fn process_server_handshake(&mut self) -> Result<(), TlsError> {
        let (_rec_type, contents) = self.read_record_to_buffer()?;

        let decrypted = decrypt(
            self.server_handshake_key.unwrap(),
            self.server_handshake_iv.unwrap(),
            contents,
        );
        self.server_handshake = Some(decrypted);
        self.make_application_keys();
        self.client_change_chipher_spec()?;
        self.client_handshake_finished()?;

        log::info!("done with handshake");
        Ok(())
    }

    fn client_handshake_finished(&mut self) -> Result<(), TlsError> {
        let verify_data = self.generate_verify_data();
        let mut msg: Buffer<8192> = Buffer::new();
        msg.push(&[0x14, 0x00, 0x00, 0x20]);
        msg.push(verify_data.slice());
        msg.push_byte(0x16);

        let additional = Buffer::new_from_slice(&[0x17, 0x03, 0x03, 0x00, 0x35]);

        let encrypted = encrypt(
            self.client_handshake_key.unwrap(),
            self.client_handshake_iv.unwrap(),
            msg,
            additional,
        );

        log::info!("client handshake finished message {:?}", encrypted.slice());
        self.stream
            .write(encrypted.slice())
            .map_err(|_| TlsError::IoError())?;
        self.stream.flush().map_err(|_| TlsError::IoError())?;
        Ok(())
    }

    pub fn generate_verify_data(&mut self) -> Buffer<8192> {
        let finished_key = self.hkdf_expand_label(
            self.client_handshake_secret.unwrap().slice(),
            b"finished",
            &[],
            32,
        );
        log::trace!("finished_key {:?}", finished_key.slice());

        let mut handshake_messages = Buffer::<8192>::new();
        handshake_messages.push(&self.client_hello.unwrap().slice()[5..]); // strip the record header
        handshake_messages.push(&self.server_hello.unwrap().slice()[5..]); // strip the record header
        handshake_messages.push(&self.server_handshake.unwrap().slice());

        let finished_hash = Sha256::digest(handshake_messages.slice());
        log::trace!("finished_hash {:?}", finished_hash.as_slice());

        type HmacSha256 = Hmac<Sha256>;

        use hmac::{Hmac, Mac};
        let mut hm = HmacSha256::new_from_slice(finished_key.slice()).unwrap();
        hm.update(finished_hash.as_slice());
        let result = hm.finalize();
        let bytes = result.into_bytes();
        log::trace!("hm {:?}", &bytes);

        Buffer::new_from_slice(&bytes)
    }

    fn client_change_chipher_spec(&mut self) -> Result<(), TlsError> {
        self.stream
            .write(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01])
            .map_err(|_| TlsError::IoError())?;
        self.stream.flush().map_err(|_| TlsError::IoError())?;
        Ok(())
    }

    fn make_application_keys(&mut self) {
        let mut handshake_messages = Buffer::<8192>::new();
        handshake_messages.push(&self.client_hello.unwrap().slice()[5..]); // strip the record header
        handshake_messages.push(&self.server_hello.unwrap().slice()[5..]); // strip the record header
        handshake_messages.push(&self.server_handshake.unwrap().slice());
        log::trace!(
            "server_handshake {:?}",
            &self.server_handshake.unwrap().slice()
        );
        log::trace!("handshake messages {:?}", handshake_messages.slice());

        let zeros = [0u8; 32];
        let derived_secret =
            self.derive_secret(self.handshake_secret.unwrap().slice(), b"derived", &[]);
        log::trace!("app derived secret {:?}", derived_secret.slice());
        let (master_secret, _) = Hkdf::<Sha256>::extract(Some(&derived_secret.slice()), &zeros);
        log::trace!("master_secret {:?}", master_secret.as_slice());

        let cap_secret = self.derive_secret(
            master_secret.as_slice(),
            b"c ap traffic",
            handshake_messages.slice(),
        );
        log::trace!("cap_secret {:?}", cap_secret.slice());
        let client_application_key = self.hkdf_expand_label(cap_secret.slice(), b"key", &[], 16);
        log::trace!(
            "client_application_key {:?}",
            client_application_key.slice()
        );
        let client_application_iv = self.hkdf_expand_label(cap_secret.slice(), b"iv", &[], 12);
        log::trace!("client_application_iv {:?}", client_application_iv.slice());

        let sap_secret = self.derive_secret(
            master_secret.as_slice(),
            b"s ap traffic",
            handshake_messages.slice(),
        );
        log::trace!("master_secret {:?}", sap_secret.slice());
        let server_application_key = self.hkdf_expand_label(sap_secret.slice(), b"key", &[], 16);
        log::trace!(
            "server_application_key {:?}",
            server_application_key.slice()
        );
        let server_application_iv = self.hkdf_expand_label(sap_secret.slice(), b"iv", &[], 12);
        log::trace!("server_application_iv {:?}", server_application_iv.slice());

        self.client_application_key = Some(Buffer::new_from_slice(client_application_key.slice()));
        self.client_application_iv = Some(Buffer::new_from_slice(client_application_iv.slice()));
        self.server_application_key = Some(Buffer::new_from_slice(server_application_key.slice()));
        self.server_application_iv = Some(Buffer::new_from_slice(server_application_iv.slice()));
    }

    fn read_record_to_buffer(&mut self) -> Result<(u8, Buffer<8192>), TlsError> {
        let mut result = Buffer::<8192>::new();

        let mut record_header = [0u8; 5];
        if self.stream.read(&mut record_header).unwrap() != 5 {
            return Err(TlsError::ReceivedUnexpectedData);
        }

        result.push(&record_header);
        let record_type = record_header[0];
        log::info!("Record type is 0x{:02x}", record_type);
        let len = ((record_header[3] as usize) << 8usize) | record_header[4] as usize;
        log::info!("Record size is {}", len);

        let mut record_content = [0u8; 8192];
        let mut read_count = 0;
        while read_count < len {
            let s = self
                .stream
                .read(&mut record_content[read_count..][..len - read_count])
                .unwrap();
            read_count += s;
        }
        result.push(&record_content[..len]);

        Ok((record_type, result))
    }

    fn make_handshake_keys(&mut self) {
        // try to calculate the shared secret and make handshake keys
        let server_pk = PublicKey::from(*self.server_public_key.as_ref().unwrap());
        let client_secret = &self.secret;
        let shared_secret = client_secret.diffie_hellman(&server_pk);
        log::info!("Calculated secret {:?}", shared_secret.as_bytes());

        // hkdf extract (hash, secret, salt)
        let zeros = [0u8; 32];
        let psk = [0u8; 32];
        let (early_secret, _) = Hkdf::<Sha256>::extract(Some(&zeros), &psk);
        log::info!("early_secret {:?}", early_secret.as_slice());

        let derived_secret = self.derive_secret(early_secret.as_slice(), b"derived", &[]);
        log::info!("derived secret {:?}", derived_secret.slice());
        let (handshake_secret, _) =
            Hkdf::<Sha256>::extract(Some(derived_secret.slice()), shared_secret.as_bytes());
        log::info!("handshake_secret {:?}", handshake_secret.as_slice());
        self.handshake_secret = Some(Buffer::new_from_slice(handshake_secret.as_slice()));

        let mut handshake_messages = Buffer::<2048>::new();
        handshake_messages.push(&self.client_hello.unwrap().slice()[5..]); // strip the record header
        handshake_messages.push(&self.server_hello.unwrap().slice()[5..]); // strip the record header
        log::info!("handshake_messages {:?}", handshake_messages.slice());

        let chs_secret = self.derive_secret(
            handshake_secret.as_slice(),
            b"c hs traffic",
            handshake_messages.slice(),
        );
        log::info!("chs_secret {:?}", chs_secret.slice());
        self.client_handshake_secret = Some(Buffer::new_from_slice(chs_secret.slice()));

        let client_handshake_key = self.hkdf_expand_label(chs_secret.slice(), b"key", &[], 16);
        let client_handshake_iv = self.hkdf_expand_label(chs_secret.slice(), b"iv", &[], 12);

        log::info!("client_handshake_key {:02x?}", client_handshake_key.slice());
        log::info!("client_handshake_iv {:02x?}", client_handshake_iv.slice());

        self.client_handshake_key = Some(client_handshake_key);
        self.client_handshake_iv = Some(client_handshake_iv);

        let shs_secret = self.derive_secret(
            handshake_secret.as_slice(),
            b"s hs traffic",
            handshake_messages.slice(),
        );
        log::info!("shs_secret {:?}", chs_secret.slice());

        let server_handshake_key = self.hkdf_expand_label(shs_secret.slice(), b"key", &[], 16);
        let server_handshake_iv = self.hkdf_expand_label(shs_secret.slice(), b"iv", &[], 12);

        log::info!("server_handshake_key {:02x?}", client_handshake_key.slice());
        log::info!("server_handshake_iv {:02x?}", client_handshake_iv.slice());

        self.server_handshake_key = Some(server_handshake_key);
        self.server_handshake_iv = Some(server_handshake_iv);
    }

    fn derive_secret(
        &self,
        secret: &[u8],
        label: &[u8],
        transcript_messages: &[u8],
    ) -> Buffer<128> {
        let hash = Sha256::digest(transcript_messages);
        self.hkdf_expand_label(secret, label, hash.as_slice(), 32)
    }

    fn hkdf_expand_label(
        &self,
        secret: &[u8],
        label: &[u8],
        context: &[u8],
        len: usize,
    ) -> Buffer<128> {
        let mut hkdf_label = Buffer::<128>::new();
        hkdf_label.push(&(len as u16).to_be_bytes());
        hkdf_label.push_byte((label.len() + 6) as u8);
        hkdf_label.push(b"tls13 ");
        hkdf_label.push(label);
        hkdf_label.push_byte(context.len() as u8);
        hkdf_label.push(context);

        let mut res_bytes = [0u8; 128];
        let hkdf = Hkdf::<Sha256>::from_prk(secret).unwrap();
        hkdf.expand(hkdf_label.slice(), &mut res_bytes[..len])
            .unwrap();

        Buffer::<128>::new_from_slice(&res_bytes[..len])
    }

    fn send_client_hello(&mut self) -> Result<(), TlsError> {
        let mut buffer: Buffer<8192> = Buffer::new();

        let mut extensions: Buffer<8192> = Buffer::new();
        extensions.push(
            self.extension(0x00, self.server_name(self.servername).slice())
                .slice(),
        );

        extensions.push(self.extension(0x0a, &[0x00, 0x02, 0x00, 0x1d]).slice()); //groups

        // signature algorithms: lots I guess, it doesn't matter because we're not going to verify it
        extensions.push(
            self.extension(
                0x0d,
                &[
                    0x00, 0x12, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05,
                    0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01,
                ],
            )
            .slice(),
        );
        extensions.push(self.extension(0x33, self.public_key().slice()).slice()); // key share
        extensions.push(self.extension(0x2d, &[0x01, 0x01]).slice()); // PSK (no effect)
        extensions.push(self.extension(0x2b, &[0x02, 0x03, 0x04]).slice()); // TLS version

        let mut handshake: Buffer<8192> = Buffer::new();
        handshake.push(&[0x03, 0x03]); // client version: TLS 1.2
        handshake.push(&self.random); // 32 bytes of random

        handshake.push(&[0x00]); // no session id
        handshake.push(&[0x00, 0x02, 0x13, 0x01]); // cipher suites: TLS_AES_128_GCM_SHA256
        handshake.push(&[0x01, 0x00]);
        handshake.push(&(extensions.len() as u16).to_be_bytes());
        handshake.push(extensions.slice());

        buffer.push(&[0x16, 0x03, 0x01]); // record header
        buffer.push(&((handshake.len() + 4) as u16).to_be_bytes());
        buffer.push(&[0x01, 0x00]); // handshake
        buffer.push(&(handshake.len() as u16).to_be_bytes());
        buffer.push(handshake.slice());

        log::trace!("Send ClientHello {:?}", buffer.slice());

        self.stream
            .write(buffer.slice())
            .map_err(|_| TlsError::IoError())?;
        self.stream.flush().map_err(|_| TlsError::IoError())?;

        self.client_hello = Some(buffer);

        Ok(())
    }

    fn extension(&self, id: u16, contents: &[u8]) -> Buffer<256> {
        let mut buffer: Buffer<256> = Buffer::new();
        buffer.push(&id.to_be_bytes());
        buffer.push(&(contents.len() as u16).to_be_bytes());
        buffer.push(contents);

        buffer
    }

    fn server_name(&self, name: &str) -> Buffer<256> {
        let mut buffer: Buffer<256> = Buffer::new();
        buffer.push(&((name.len() + 3) as u16).to_be_bytes());
        buffer.push_byte(0x00);
        buffer.push(&(name.len() as u16).to_be_bytes());
        buffer.push(name.as_bytes());

        buffer
    }

    fn public_key(&self) -> Buffer<256> {
        let pk = PublicKey::from(&self.secret);
        let public_key = pk.as_bytes();
        log::trace!("PK {:02x?}", public_key);
        log::trace!("PK {}", public_key.len());

        let mut buffer: Buffer<256> = Buffer::new();
        buffer.push(&((public_key.len() + 4) as u16).to_be_bytes());
        buffer.push(&[0x00, 0x1d]); // x25519
        buffer.push(&(public_key.len() as u16).to_be_bytes());
        buffer.push(public_key);

        buffer
    }

    pub fn encrypt_application_data(&self, mut data: Buffer<8192>) -> Buffer<8192> {
        data.push_byte(0x17);
        let mut additional: Buffer<256> = Buffer::new_from_slice(&[0x17, 0x03, 0x03]);
        additional.push(&((data.len() + 16) as u16).to_be_bytes());
        encrypt(
            self.client_application_key.unwrap(),
            self.client_application_iv.unwrap(),
            data,
            additional,
        )
    }

    pub fn send_data(&mut self, data: Buffer<8192>) -> Result<(), TlsError> {
        let encrypted = self.encrypt_application_data(data);
        // we should do the modification of the IV here like in receive_data
        // without we can only ever successfully send one single record!
        self.records_sent += 1;
        self.stream
            .write(encrypted.slice())
            .map_err(|_| TlsError::IoError())?;
        self.stream.flush().map_err(|_| TlsError::IoError())?;
        Ok(())
    }

    pub fn receive_data(&mut self) -> Result<Buffer<8192>, TlsError> {
        let (_, record) = self.read_record_to_buffer()?;
        let mut iv = Buffer::new_from_slice(self.server_application_iv.unwrap().slice());
        // this will only work until received record 255
        iv.slice_mut()[11] ^= self.records_received as u8;
        let plaintext = decrypt(self.server_application_key.unwrap(), iv, record);
        self.records_received += 1;
        Ok(plaintext)
    }
}

fn decrypt(key: Buffer<128>, iv: Buffer<128>, contents: Buffer<8192>) -> Buffer<8192> {
    let key = Key::from_slice(key.slice());
    let cipher = Aes128Gcm::new(key);

    let nonce = Nonce::from_slice(iv.slice()); // 96-bits; unique per message

    let mut buffer = Buffer::<8192>::new_from_slice(&contents.slice()[5..]);
    cipher
        .decrypt_in_place(nonce, &contents.slice()[..5], &mut buffer)
        .unwrap();

    buffer
}

fn encrypt(
    key: Buffer<128>,
    iv: Buffer<128>,
    plaintext: Buffer<8192>,
    additional: Buffer<256>,
) -> Buffer<8192> {
    let key = Key::from_slice(key.slice());
    let cipher = Aes128Gcm::new(key);

    let nonce = Nonce::from_slice(iv.slice()); // 96-bits; unique per message

    let mut buffer = Buffer::<8192>::new_from_slice(&plaintext.slice());
    cipher
        .encrypt_in_place(nonce, &additional.slice(), &mut buffer)
        .unwrap();

    let mut res = Buffer::<8192>::new();
    res.push(additional.slice());
    res.push(buffer.slice());
    res
}
