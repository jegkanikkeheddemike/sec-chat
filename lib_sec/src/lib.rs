use rand::rngs::OsRng;
use serde::de::DeserializeOwned;
use thiserror::Error;

use rsa::{
    pkcs1::{self, DecodeRsaPrivateKey, EncodeRsaPrivateKey},
    Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey,
};
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
const BITS: usize = 4096;
const ENC_CHUNK_SIZE: usize = BITS / 8 - 11;
const DEC_CHUNK_SIZE: usize = BITS / 8;

pub async fn key_gen_and_save() -> Result<(RsaPrivateKey, RsaPublicKey), UserKPError> {
    println!("RUNNING KEYGEN");
    let mut rng = OsRng::default();
    let priv_key = RsaPrivateKey::new(&mut rng, BITS).unwrap();

    let priv_key_doc = priv_key.to_pkcs1_pem(pkcs1::LineEnding::LF).unwrap();
    let priv_key_bytes = priv_key_doc.as_bytes();

    let pub_key = RsaPublicKey::from(&priv_key);

    let Some(mut home) = dirs::home_dir() else {
        return Err(UserKPError::NoHomeDir);
    };
    home.push(KEY_FILE_NAME);

    tokio::fs::write(home, priv_key_bytes).await?;

    Ok((priv_key, pub_key))
}

#[derive(Debug, Error)]
pub enum WriteEncMsgError {
    #[error("IO error")]
    IoError(#[from] io::Error),
    #[error("Serialization error")]
    SerializationError(#[from] bincode::Error),
    #[error("Encryption error")]
    EncError(#[from] rsa::Error),
}

pub async fn write_encrypted_msg<W: AsyncWriteExt + std::marker::Unpin, M: serde::Serialize>(
    writer: &mut W,
    message: &M,
    pub_key: &RsaPublicKey,
) -> Result<(), WriteEncMsgError> {
    let mut buffer = vec![0; 8];
    bincode::serialize_into(&mut buffer, message)?;
    let len_bytes = (buffer.len() - 8).to_be_bytes();
    for (index, byte) in len_bytes.into_iter().enumerate() {
        buffer[index] = byte;
    }

    let mut write_buffer = vec![];

    let mut rng = OsRng::default();
    for chunk_res in buffer
        .chunks(ENC_CHUNK_SIZE)
        .map(|chunk| pub_key.encrypt(&mut rng, Pkcs1v15Encrypt, chunk))
    {
        write_buffer.append(&mut chunk_res?);
    }

    writer.write(&write_buffer).await?;
    Ok(())
}
#[derive(Debug, Error)]
pub enum ReadEncError {
    #[error("IO error")]
    IoError(#[from] io::Error),
    #[error("Invalid msg format. Missing len bytes")]
    InvalidMsgFormat,
    #[error("Decryption error")]
    DecryptionError(#[from] rsa::Error),
    #[error("Deserializaton failed")]
    DeserializationError(#[from] bincode::Error),
}

pub async fn read_decrypted_msg<R: AsyncReadExt + std::marker::Unpin, M: DeserializeOwned>(
    reader: &mut R,
    priv_key: &RsaPrivateKey,
) -> Result<M, ReadEncError> {
    let mut buffer = vec![0u8; DEC_CHUNK_SIZE];

    reader.read_exact(&mut buffer).await?;
    let dec_bytes = priv_key.decrypt(Pkcs1v15Encrypt, &buffer)?;

    let Ok(len_bytes) = dec_bytes[0..8].try_into() else {
        return Err(ReadEncError::InvalidMsgFormat);
    };

    let msg_len = usize::from_be_bytes(len_bytes);
    let mut msg_bytes = Vec::with_capacity(msg_len);
    msg_bytes.extend_from_slice(&dec_bytes[8..]);

    while msg_bytes.len() < msg_len {
        reader.read_exact(&mut buffer).await?;
        let mut dec_bytes = priv_key.decrypt(Pkcs1v15Encrypt, &buffer)?;
        msg_bytes.append(&mut dec_bytes);
    }

    Ok(bincode::deserialize(&msg_bytes)?)
}

#[derive(Debug, Error)]
pub enum UserKPError {
    #[error("IO error")]
    IOError(#[from] io::Error),
    #[error("Computer has no home dir")]
    NoHomeDir,
    #[error("Loaded an invalid private key")]
    InvalidKeyError(#[from] pkcs1::Error),
}

const KEY_FILE_NAME: &str = ".sec_chat";

pub fn keypair_exists() -> Result<bool, UserKPError> {
    let Some(mut home) = dirs::home_dir() else {
        return Err(UserKPError::NoHomeDir);
    };
    home.push(KEY_FILE_NAME);
    return Ok(home.exists());
}

pub async fn load_user_keypair() -> Result<(RsaPrivateKey, RsaPublicKey), UserKPError> {
    if !keypair_exists().unwrap() {
        return key_gen_and_save().await;
    }

    let Some(mut home) = dirs::home_dir() else {
        return Err(UserKPError::NoHomeDir);
    };
    home.push(KEY_FILE_NAME);

    let priv_raw = tokio::fs::read_to_string(home).await?;

    let priv_key = RsaPrivateKey::from_pkcs1_pem(&priv_raw)?;
    let pub_key = priv_key.to_public_key();

    return Ok((priv_key, pub_key));
}
