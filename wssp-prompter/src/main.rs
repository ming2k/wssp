use adw::prelude::*;
use adw::Application;
use gtk4 as gtk;
use libadwaita as adw;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use wssp_common::ipc::PromptResponse;

fn main() -> gtk::glib::ExitCode {
    let app = Application::builder()
        .application_id("com.hihusky.wssp.Prompter")
        .build();

    app.connect_activate(|app| {
        adw::StyleManager::default().set_color_scheme(adw::ColorScheme::Default);
        build_ui(app);
    });

    app.run()
}

fn build_ui(app: &Application) {
    let window = adw::Window::builder()
        .application(app)
        .title("Vault Unlock")
        .default_width(360)
        .resizable(false)
        .modal(true)
        .build();

    let content = gtk::Box::new(gtk::Orientation::Vertical, 0);
    let vbox = gtk::Box::new(gtk::Orientation::Vertical, 18);
    vbox.set_margin_top(32);
    vbox.set_margin_bottom(32);
    vbox.set_margin_start(32);
    vbox.set_margin_end(32);

    let title = gtk::Label::builder()
        .label("Enter Vault Password")
        .css_classes(["title-2"])
        .build();
    vbox.append(&title);

    let description = gtk::Label::builder()
        .label("Please provide the master password to continue.")
        .wrap(true)
        .justify(gtk::Justification::Center)
        .css_classes(["caption"])
        .build();
    vbox.append(&description);

    let password_entry = gtk::PasswordEntry::builder()
        .placeholder_text("Master Password")
        .activates_default(true)
        .build();
    vbox.append(&password_entry);

    let error_label = gtk::Label::builder()
        .label("Password cannot be empty.")
        .css_classes(["error"])
        .visible(false)
        .build();
    vbox.append(&error_label);

    let unlock_button = gtk::Button::builder()
        .label("Unlock")
        .css_classes(["suggested-action"])
        .margin_top(6)
        .build();
    window.set_default_widget(Some(&unlock_button));
    vbox.append(&unlock_button);

    let window_clone = window.clone();
    let entry_clone = password_entry.clone();
    let error_clone = error_label.clone();

    let perform_unlock = move || {
        let password = entry_clone.text().to_string();
        if password.is_empty() {
            error_clone.set_visible(true);
        } else {
            send_password(password);
            window_clone.close();
        }
    };

    password_entry.connect_changed({
        let error_label = error_label.clone();
        move |_| error_label.set_visible(false)
    });
    unlock_button.connect_clicked({
        let f = perform_unlock.clone();
        move |_| f()
    });
    password_entry.connect_activate(move |_| perform_unlock());

    let key_controller = gtk::EventControllerKey::new();
    let window_for_esc = window.clone();
    key_controller.connect_key_pressed(move |_, key, _, _| {
        if key == gtk::gdk::Key::Escape {
            window_for_esc.close();
        }
        gtk::glib::Propagation::Proceed
    });
    window.add_controller(key_controller);

    content.append(&vbox);
    window.set_content(Some(&content));
    window.present();
    password_entry.grab_focus();
}

fn send_password(password: String) {
    let runtime_dir = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".to_string());
    let socket_path = PathBuf::from(runtime_dir).join("wssp.sock");

    match UnixStream::connect(&socket_path) {
        Ok(mut stream) => {
            let response = PromptResponse { password: Some(password) };
            if let Ok(serialized) = serde_json::to_vec(&response) {
                let _ = stream.write_all(&serialized);
            }
        }
        Err(e) => eprintln!("Failed to connect to daemon socket: {}", e),
    }
}
