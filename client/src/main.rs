use lib_sec::read_decrypted_msg;
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::{RsaPrivateKey, RsaPublicKey};
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

#[tokio::main]
async fn main() {
    let (user_id, pub_key, priv_key, stream) = authorize().await;
}

async fn authorize() -> (String, RsaPublicKey, RsaPrivateKey, TcpStream) {
    let mut user_id_path = dirs::home_dir().unwrap();
    user_id_path.push(".sec_chat_id");

    match fs::read_to_string(&user_id_path).await {
        Ok(user_id) => login(user_id).await,
        Err(_) => signup().await,
    }
}

async fn login(user_id: String) -> (String, RsaPublicKey, RsaPrivateKey, TcpStream) {
    println!("AUTH WITH LOGIN");
    let mut stream = TcpStream::connect("0.0.0.0:7685").await.unwrap();

    let (priv_key, pub_key) = lib_sec::load_user_keypair().await.unwrap();

    stream.write(b"LOGIN\n").await.unwrap();

    stream.write(user_id.as_bytes()).await.unwrap();
    stream.write(b"\n").await.unwrap();

    let nonce_str: String = lib_sec::read_decrypted_msg(&mut stream, &priv_key)
        .await
        .unwrap();

    stream.write(nonce_str.as_bytes()).await.unwrap();
    stream.write(b"\n").await.unwrap();
    stream.flush().await.unwrap();

    (user_id, pub_key, priv_key, stream)
}

async fn signup() -> (String, RsaPublicKey, RsaPrivateKey, TcpStream) {
    println!("AUTH WITH SIGNUP");
    let mut stream = TcpStream::connect("0.0.0.0:7685").await.unwrap();

    let (priv_key, pub_key) = lib_sec::load_user_keypair().await.unwrap();

    let pub_key_str = pub_key.to_pkcs1_pem(rsa::pkcs8::LineEnding::LF).unwrap();

    stream.write(b"SIGNUP\n").await.unwrap();
    stream.write(pub_key_str.as_bytes()).await.unwrap();
    stream.write(b"\n").await.unwrap();

    stream.flush().await.unwrap();

    let nonce_str: String = lib_sec::read_decrypted_msg(&mut stream, &priv_key)
        .await
        .unwrap();

    stream.write(nonce_str.as_bytes()).await.unwrap();
    stream.write(b"\n").await.unwrap();
    stream.flush().await.unwrap();

    let user_id: String = read_decrypted_msg(&mut stream, &priv_key).await.unwrap();
    println!("Signed up with user-id: {user_id}");

    let mut user_id_path = dirs::home_dir().unwrap();
    user_id_path.push(".sec_chat_id");
    fs::write(user_id_path, user_id.as_bytes()).await.unwrap();

    (user_id, pub_key, priv_key, stream)
}
