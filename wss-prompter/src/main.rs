use adw::prelude::*;
use adw::Application;
use gtk4 as gtk;
use libadwaita as adw;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use wss_common::ipc::PromptResponse;

fn main() -> gtk::glib::ExitCode {
    let app = Application::builder()
        .application_id("com.hihusky.wssp.Prompter")
        .build();

    app.connect_activate(|app| {
        // Use AdwStyleManager to handle color schemes instead of legacy GtkSettings
        adw::StyleManager::default().set_color_scheme(adw::ColorScheme::Default);
        build_ui(app);
    });

    app.run()
}

fn build_ui(app: &Application) {
    let mode = std::env::var("WSSP_PROMPT_MODE").unwrap_or_else(|_| "unlock".to_string());
    let is_create = mode == "create";

    let window = adw::Window::builder()
        .application(app)
        .title(if is_create { "Setup Vault" } else { "Vault Unlock" })
        .default_width(360)
        .resizable(false)
        .build();

    // Remove the HeaderBar and use a simple vertical box
    let content = gtk::Box::new(gtk::Orientation::Vertical, 0);
    
    // Main layout
    let vbox = gtk::Box::new(gtk::Orientation::Vertical, 18);
    vbox.set_margin_top(32);
    vbox.set_margin_bottom(32);
    vbox.set_margin_start(32);
    vbox.set_margin_end(32);

    let label = gtk::Label::builder()
        .label(if is_create { "Set Master Password" } else { "Enter Vault Password" })
        .css_classes(["title-2"])
        .build();
    vbox.append(&label);

    let description = gtk::Label::builder()
        .label(if is_create {
            "Create a master password to secure your vault. Don't lose it!"
        } else {
            "Please provide the master password to continue."
        })
        .wrap(true)
        .justify(gtk::Justification::Center)
        .css_classes(["caption"])
        .build();
    vbox.append(&description);

    let password_entry = gtk::PasswordEntry::builder()
        .placeholder_text(if is_create { "New Master Password" } else { "Master Password" })
        .activates_default(true)
        .build();
    vbox.append(&password_entry);

    let unlock_button = gtk::Button::builder()
        .label(if is_create { "Create Vault" } else { "Unlock" })
        .css_classes(["suggested-action"])
        .margin_top(6)
        .build();

    let window_clone = window.clone();
    let entry_clone = password_entry.clone();

    // Use a shared function for unlocking
    let perform_unlock = move || {
        let password = entry_clone.text().to_string();
        if !password.is_empty() {
            send_password(password);
            window_clone.close();
        }
    };

    let unlock_fn = perform_unlock.clone();
    unlock_button.connect_clicked(move |_| unlock_fn());
    
    // Allow pressing Enter to unlock
    password_entry.connect_activate(move |_| perform_unlock());

    vbox.append(&unlock_button);

    // Add ESC key support
    let key_controller = gtk::EventControllerKey::new();
    let window_for_esc = window.clone();
    key_controller.connect_key_pressed(move |_, key, _, _| {
        if key == gtk::gdk::Key::Escape {
            window_for_esc.close();
            gtk::glib::Propagation::Proceed
        } else {
            gtk::glib::Propagation::Proceed
        }
    });
    window.add_controller(key_controller);

    content.append(&vbox);
    window.set_content(Some(&content));
    window.present();
}

fn send_password(password: String) {
    let runtime_dir = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".to_string());
    let socket_path = PathBuf::from(runtime_dir).join("wssp.sock");

    match UnixStream::connect(&socket_path) {
        Ok(mut stream) => {
            let response = PromptResponse {
                password: Some(password),
            };
            if let Ok(serialized) = serde_json::to_vec(&response) {
                let _ = stream.write_all(&serialized);
            }
        }
        Err(e) => {
            eprintln!("Failed to connect to daemon socket: {}", e);
        }
    }
}
