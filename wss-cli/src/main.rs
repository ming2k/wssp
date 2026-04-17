use std::env;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use wss_common::ipc::PromptResponse;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: wss-cli unlock <password>");
        std::process::exit(1);
    }

    if args[1] == "unlock" {
        if args.len() < 3 {
            eprintln!("Error: Password required");
            std::process::exit(1);
        }
        let password = args[2].clone();

        let runtime_dir = env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".to_string());
        let socket_path = PathBuf::from(runtime_dir).join("wssp.sock");

        if !socket_path.exists() {
            eprintln!("Daemon is not currently requesting a password (socket not found).");
            std::process::exit(1);
        }

        match UnixStream::connect(&socket_path) {
            Ok(mut stream) => {
                let response = PromptResponse {
                    password: Some(password),
                };
                if let Ok(serialized) = serde_json::to_vec(&response) {
                    let _ = stream.write_all(&serialized);
                    println!("Password sent to daemon successfully.");
                } else {
                    eprintln!("Failed to serialize password.");
                }
            }
            Err(e) => {
                eprintln!("Failed to connect to daemon socket: {}", e);
            }
        }
    } else {
        eprintln!("Unknown command: {}", args[1]);
    }
}
