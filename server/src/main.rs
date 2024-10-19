use rsa::{pkcs1::DecodeRsaPublicKey, RsaPublicKey};
use sqlx::{mysql::MySqlPoolOptions, MySql, Pool};
use std::{env, net::SocketAddr};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
};

#[tokio::main]
async fn main() {
    dotenv::dotenv().unwrap();

    let pool = MySqlPoolOptions::new()
        .max_connections(16)
        .connect(&env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();

    let server = tokio::net::TcpListener::bind("0.0.0.0:7685").await.unwrap();

    loop {
        match server.accept().await {
            Err(err) => {
                eprintln!("Failed to accept connection: {err:#?}");
            }
            Ok((stream, addr)) => {
                tokio::spawn(accept_client(stream, addr, pool.clone()));
            }
        }
    }
}

async fn accept_client(stream: TcpStream, _addr: SocketAddr, pool: Pool<MySql>) {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    let Some((pub_key, user_id)) = authorize_client(&mut reader, &mut writer, &pool).await else {
        return;
    };

    run_authed_client(user_id, pub_key, &mut reader, &mut writer, _addr, &pool).await;
}

async fn authorize_client<R: AsyncReadExt + Unpin, W: AsyncWriteExt + Unpin>(
    reader: &mut BufReader<R>,
    writer: &mut W,
    pool: &Pool<MySql>,
) -> Option<(RsaPublicKey, String)> {
    let mut auth_method = String::new();
    reader.read_line(&mut auth_method).await.unwrap();

    match auth_method.trim() {
        "LOGIN" => {
            let mut user_id = String::new();
            reader.read_line(&mut user_id).await.unwrap();

            let user_record = sqlx::query!(
                "select public_key from users where user_id = ?",
                user_id.trim()
            )
            .fetch_one(pool)
            .await
            .unwrap();

            let pub_key = RsaPublicKey::from_pkcs1_pem(&user_record.public_key).unwrap();

            if let Err((real_nonce, read_nonce)) = verify_nonce(reader, writer, &pub_key).await {
                eprintln!(
                    "Invalid proof-of-identity response during login: real={real_nonce}, received={read_nonce}"
                );
                return None;
            }
            Some((pub_key, user_id))
        }
        "SIGNUP" => {
            let mut pub_key_str = String::new();

            loop {
                reader.read_line(&mut pub_key_str).await.unwrap();
                if pub_key_str.ends_with("-----END RSA PUBLIC KEY-----\n") {
                    break;
                }
            }

            let pub_key = RsaPublicKey::from_pkcs1_pem(&pub_key_str).unwrap();

            if let Err((real_nonce, read_nonce)) = verify_nonce(reader, writer, &pub_key).await {
                eprintln!(
                    "Invalid proof-of-identity response during signup: real={real_nonce}, received={read_nonce}"
                );
                return None;
            }

            let (user_id_bytes,): (Vec<u8>,) = sqlx::query_as(
                "insert into users (public_key) values (?) returning user_id as new_user_id",
            )
            .bind(pub_key_str)
            .fetch_one(pool)
            .await
            .unwrap();

            let user_id_string = String::from_utf8(user_id_bytes).unwrap();
            // Send new userid to the user
            lib_sec::write_encrypted_msg(writer, &user_id_string, &pub_key)
                .await
                .unwrap();

            Some((pub_key, user_id_string))
        }

        invalid => {
            eprintln!("Invalid protocol. Init read: {invalid:#?}");
            None
        }
    }
}

async fn verify_nonce<R: AsyncReadExt + Unpin, W: AsyncWriteExt + Unpin>(
    reader: &mut BufReader<R>,
    writer: &mut W,
    pub_key: &RsaPublicKey,
) -> Result<(), (String, String)> {
    let nonce = format!("{}", rand::random::<u128>());

    lib_sec::write_encrypted_msg(writer, &nonce, pub_key)
        .await
        .unwrap();

    // For some reason there are some extra empty newlines.
    // just ignore them
    let mut nonce_buffer = String::new();
    while nonce_buffer.trim().is_empty() {
        nonce_buffer.clear();
        reader.read_line(&mut nonce_buffer).await.unwrap();
    }

    if nonce_buffer.trim() == nonce {
        Ok(())
    } else {
        Err((nonce, nonce_buffer))
    }
}

async fn run_authed_client<R: AsyncReadExt, W: AsyncWriteExt>(
    user_id: String,
    pub_key: RsaPublicKey,
    reader: &mut BufReader<R>,
    writer: &mut W,
    _addr: SocketAddr,
    pool: &Pool<MySql>,
) {
}
