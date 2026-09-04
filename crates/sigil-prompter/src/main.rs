use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use iris::{Application, Config};
use lens::{Frame, Input, TextBuf};
use sigil_ipc::PromptResponse;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args()
        .nth(1)
        .as_deref()
        .is_some_and(|a| a == "--version" || a == "-V")
    {
        println!("{} {}", env!("CARGO_BIN_NAME"), env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    let mut state = PrompterState::new();
    let config = Config::new("Vault Unlock")?
        .app_id("org.sigil.Prompter")?
        .size(420, 260);

    Application::run(
        config,
        move |frame, input| state.build(frame, input),
        None::<fn(iris::PaintHost)>,
    )?;

    Ok(())
}

struct PrompterState {
    password: TextBuf,
    error_message: Option<&'static str>,
}

impl PrompterState {
    fn new() -> Self {
        Self {
            password: TextBuf::new(256, ""),
            error_message: None,
        }
    }

    fn submit(&mut self) {
        let text = self.password.as_str();
        let pwd = text.trim();
        if pwd.is_empty() {
            self.error_message = Some("Password cannot be empty.");
        } else {
            send_password(pwd.to_string());
            iris::window_close();
        }
    }

    fn build(&mut self, frame: &mut Frame, input: &Input) {
        let raw = input.as_raw();
        for ev in &raw.keys[..raw.key_count as usize] {
            if !ev.pressed {
                continue;
            }
            if ev.key == lens::key::ESCAPE {
                iris::window_close();
                return;
            }
            if ev.key == lens::key::RETURN {
                self.submit();
                return;
            }
        }

        let mut trigger_submit = false;
        let mut trigger_cancel = false;

        frame
            .col()
            .pad(24.0)
            .gap(12.0)
            .items_center()
            .show(|frame| {
                frame.label_sized("Enter Vault Password", 18.0);
                frame.label("Please provide the master password to continue.");

                frame.spacer(4.0);

                if frame.textfield_password("##pwd", &mut self.password, "Master Password") {
                    if self.error_message.is_some() {
                        self.error_message = None;
                    }
                }

                if let Some(err) = self.error_message {
                    frame.label_sized(err, 12.0);
                } else {
                    frame.spacer(14.0);
                }

                frame.spacer(4.0);

                frame
                    .row()
                    .gap(16.0)
                    .items_center()
                    .show(|frame| {
                        if frame.button("Cancel") {
                            trigger_cancel = true;
                        }
                        if frame.button_primary("Unlock") {
                            trigger_submit = true;
                        }
                    });
            });

        if trigger_cancel {
            iris::window_close();
        } else if trigger_submit {
            self.submit();
        }
    }
}

fn send_password(password: String) {
    let socket_path = if let Ok(path) = std::env::var("SIGIL_SOCKET_PATH") {
        PathBuf::from(path)
    } else {
        let runtime_dir = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".to_string());
        let candidate = PathBuf::from(&runtime_dir).join("sigil/native.sock");
        if candidate.exists() {
            candidate
        } else {
            PathBuf::from(runtime_dir).join("sigil.sock")
        }
    };

    match UnixStream::connect(&socket_path) {
        Ok(mut stream) => {
            let response = PromptResponse {
                password: Some(password),
            };
            if let Ok(serialized) = serde_json::to_vec(&response) {
                let _ = stream.write_all(&serialized);
            }
        }
        Err(e) => eprintln!("Failed to connect to daemon socket at {:?}: {}", socket_path, e),
    }
}
