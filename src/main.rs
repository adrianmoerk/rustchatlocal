use std::net::{TcpStream, TcpListener, SocketAddr};
use std::io::{self, BufReader, BufRead, Write};
use std::thread;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm,
};
use aes_gcm::aead::generic_array::GenericArray;
use rand::Rng;

struct ChatClient {
    username: String,
    encryption_key: [u8; 32],
    connections: Arc<Mutex<HashMap<SocketAddr, TcpStream>>>,
}

impl ChatClient {
    fn new(username: String) -> Self {
        let mut rng = rand::thread_rng();
        let encryption_key: [u8; 32] = rng.gen();
        ChatClient {
            username,
            encryption_key,
            connections: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn start(&self, listen_addr: SocketAddr) -> io::Result<()> {
        let listener = TcpListener::bind(listen_addr)?;
        println!("Listening on {}", listen_addr);

        let connections = Arc::clone(&self.connections);
        let username = self.username.clone();
        let encryption_key = self.encryption_key;

        // Thread for accepting new connections
        thread::spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        let addr = stream.peer_addr().unwrap();
                        connections.lock().unwrap().insert(addr, stream.try_clone().unwrap());
                        let conn_clone = Arc::clone(&connections);
                        let username_clone = username.clone();
                        thread::spawn(move || {
                            handle_connection(stream, addr, conn_clone, &username_clone, &encryption_key);
                        });
                    }
                    Err(e) => eprintln!("Error: {}", e),
                }
            }
        });

        self.handle_user_input()
    }

    fn handle_user_input(&self) -> io::Result<()> {
        loop {
            println!("Enter command (connect <ip:port>, send <message>, quit):");
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            let parts: Vec<&str> = input.trim().splitn(2, ' ').collect();

            match parts[0] {
                "connect" => {
                    if parts.len() != 2 {
                        println!("Usage: connect <ip:port>");
                        continue;
                    }
                    let addr: SocketAddr = parts[1].parse().expect("Invalid address");
                    self.connect_to_peer(addr)?;
                }
                "send" => {
                    if parts.len() != 2 {
                        println!("Usage: send <message>");
                        continue;
                    }
                    self.broadcast_message(parts[1])?;
                }
                "quit" => break,
                _ => println!("Unknown command"),
            }
        }
        Ok(())
    }

    fn connect_to_peer(&self, addr: SocketAddr) -> io::Result<()> {
        let stream = TcpStream::connect(addr)?;
        println!("Connected to {}", addr);
        self.connections.lock().unwrap().insert(addr, stream.try_clone()?);
        let conn_clone = Arc::clone(&self.connections);
        let username_clone = self.username.clone();
        let encryption_key = self.encryption_key;
        thread::spawn(move || {
            handle_connection(stream, addr, conn_clone, &username_clone, &encryption_key);
        });
        Ok(())
    }

    fn broadcast_message(&self, message: &str) -> io::Result<()> {
        let encrypted = encrypt(message.as_bytes(), &self.encryption_key);
        for stream in self.connections.lock().unwrap().values_mut() {
            stream.write_all(&encrypted)?;
            stream.write_all(b"\n")?;
        }
        Ok(())
    }
}

fn handle_connection(
    stream: TcpStream,
    addr: SocketAddr,
    connections: Arc<Mutex<HashMap<SocketAddr, TcpStream>>>,
    username: &str,
    encryption_key: &[u8; 32],
) {
    let mut reader = BufReader::new(stream);
    let mut buffer = Vec::new();

    loop {
        buffer.clear();
        match reader.read_until(b'\n', &mut buffer) {
            Ok(0) => break, // EOF
            Ok(_) => {
                let decrypted = decrypt(&buffer, encryption_key);
                let message = String::from_utf8_lossy(&decrypted);
                println!("{}: {}", addr, message.trim());
            }
            Err(e) => {
                eprintln!("Error reading from {}: {}", addr, e);
                break;
            }
        }
    }

    println!("{} disconnected", addr);
    connections.lock().unwrap().remove(&addr);
}

fn encrypt(data: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
    let nonce = GenericArray::from_slice(b"unique nonce"); // In a real app, use a unique nonce for each encryption
    cipher.encrypt(nonce, data).expect("encryption failure!")
}

fn decrypt(encrypted_data: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
    let nonce = GenericArray::from_slice(b"unique nonce"); // Use the same nonce as in encryption
    cipher.decrypt(nonce, encrypted_data).expect("decryption failure!")
}

fn main() -> io::Result<()> {
    println!("Enter your username:");
    let mut username = String::new();
    io::stdin().read_line(&mut username)?;
    let username = username.trim().to_string();

    println!("Enter the port to listen on:");
    let mut port = String::new();
    io::stdin().read_line(&mut port)?;
    let port: u16 = port.trim().parse().expect("Invalid port number");

    let client = ChatClient::new(username);
    client.start(SocketAddr::from(([0, 0, 0, 0], port)))
}
