use std::{
    io::{Read, Write},
    net::{TcpStream, UdpSocket},
    time::Duration,
};

use sha2::{Digest, Sha256};
use snow::{params::NoiseParams, Builder};

fn find_server_by_beacon() -> Result<String, String> {
    let socket = UdpSocket::bind("0.0.0.0:9999").map_err(|e| e.to_string())?;
    socket
        .set_read_timeout(Some(Duration::from_secs(15)))
        .map_err(|e| e.to_string())?;

    let mut buf = [0_u8; 1024];
    let (size, remote_addr) = socket.recv_from(&mut buf).map_err(|e| e.to_string())?;

    if &buf[..size] == b"NOISE_SERVER_8080" {
        Ok(format!("{}:8080", remote_addr.ip()))
    } else {
        Err("Received an unexpected server beacon".to_string())
    }
}

fn shutdown_pc_impl() -> Result<String, String> {
    let server_addr = find_server_by_beacon()?;

    let mut conn = TcpStream::connect(&server_addr).map_err(|e| e.to_string())?;
    conn.set_read_timeout(Some(Duration::from_secs(15)))
        .map_err(|e| e.to_string())?;
    conn.set_write_timeout(Some(Duration::from_secs(15)))
        .map_err(|e| e.to_string())?;

    let psk = Sha256::digest(b"mylittle-r1xe<3");
    let params = "Noise_XXpsk0_25519_AESGCM_SHA256"
        .parse::<NoiseParams>()
        .map_err(|e| e.to_string())?;
    let key_builder: Builder<'_> = Builder::new(params.clone());
    let static_key = key_builder.generate_keypair().map_err(|e| e.to_string())?;

    let mut handshake = Builder::new(params)
        .local_private_key(&static_key.private)
        .psk(0, &psk)
        .prologue(b"demo-app-v1")
        .build_initiator()
        .map_err(|e| e.to_string())?;

    let mut buffer = [0_u8; 2048];
    let first_len = handshake
        .write_message(&[], &mut buffer)
        .map_err(|e| e.to_string())?;
    conn.write_all(&buffer[..first_len])
        .map_err(|e| e.to_string())?;

    let read_len = conn.read(&mut buffer).map_err(|e| e.to_string())?;
    handshake
        .read_message(&buffer[..read_len], &mut [])
        .map_err(|e| e.to_string())?;

    let second_len = handshake
        .write_message(&[], &mut buffer)
        .map_err(|e| e.to_string())?;
    conn.write_all(&buffer[..second_len])
        .map_err(|e| e.to_string())?;

    let mut transport = handshake
        .into_transport_mode()
        .map_err(|e| e.to_string())?;

    let command_len = transport
        .write_message(b"shutdown\n", &mut buffer)
        .map_err(|e| e.to_string())?;
    conn.write_all(&buffer[..command_len])
        .map_err(|e| e.to_string())?;

    let response_len = conn.read(&mut buffer).map_err(|e| e.to_string())?;
    let mut plaintext = [0_u8; 2048];
    let plaintext_len = transport
        .read_message(&buffer[..response_len], &mut plaintext)
        .map_err(|e| e.to_string())?;
    let response = String::from_utf8_lossy(&plaintext[..plaintext_len])
        .trim()
        .to_string();

    Ok(if response.is_empty() {
        format!("Connected to {server_addr} and sent shutdown")
    } else {
        response
    })
}

#[tauri::command]
async fn shutdown_pc() -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(shutdown_pc_impl)
        .await
        .map_err(|e| e.to_string())?
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![shutdown_pc])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
