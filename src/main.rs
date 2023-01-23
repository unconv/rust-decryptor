use openssl::pkey::PKey;
use base64::Engine;
use std::fs;
use anyhow::{anyhow, Result};
use gtk::prelude::*;
use gtk::{FileChooserButton, Entry, Button};

fn build_gui() {
    if gtk::init().is_err() {
        println!("Failed to initialize GTK.");
        return;
    }

    let window = gtk::Window::new(gtk::WindowType::Toplevel);
    window.set_title("Decryption tool");
    window.set_default_size(300, 100);

    let file_input = FileChooserButton::new("Select private key file", gtk::FileChooserAction::Open);
    let text_input = Entry::new();
    let decrypt_button = Button::with_label("Decrypt");

    let vbox = gtk::Box::new(gtk::Orientation::Vertical, 5);
    vbox.pack_start(&file_input, true, true, 0);
    vbox.pack_start(&text_input, true, true, 0);
    vbox.pack_start(&decrypt_button, true, true, 0);

    window.add(&vbox);

    window.show_all();

    window.connect_delete_event(|_, _| {
        gtk::main_quit();
        Inhibit(false)
    });

    decrypt_button.connect_clicked(move |_| {
        match decrypt_from_gui(&file_input, &text_input) {
            Ok(decrypted_data) => text_input.set_text(&decrypted_data),
            Err(e) => {
                if e.to_string() == "No keyfile selected" {
                    text_input.set_text("<please select keyfile>");
                } else {
                    text_input.set_text("<unable to decrypt>");
                }
            }
        }
    });

    gtk::main();
}

fn decrypt_from_gui(file_input: &FileChooserButton, text_input: &Entry) -> Result<String, anyhow::Error> {
    match file_input.filename() {
        Some(private_key_path) => {
            let private_key = fs::read_to_string(private_key_path)?;
            let encrypted_data = text_input.text();
            let decrypted_data = decrypt(encrypted_data.as_str(), &private_key)?;
            Ok(decrypted_data)
        },
        None => {
            Err(anyhow!("No keyfile selected"))
        }
    }
}

pub fn decrypt(data: &str, private_key: &str) -> Result<String, anyhow::Error> {
    let decoded_data = base64::engine::general_purpose::STANDARD.decode(data.trim())?;

    let pkey = PKey::private_key_from_pem(private_key.as_bytes())?.rsa()?;
    let mut decrypted_data = vec![0; pkey.size() as usize];
    pkey.private_decrypt(&decoded_data, &mut decrypted_data, openssl::rsa::Padding::PKCS1)?;

    let decrypted_data_string = String::from_utf8(decrypted_data)?.trim_matches(char::from(0)).to_string();

    Ok(decrypted_data_string)
}

fn main() {
    build_gui();
}
