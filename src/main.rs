use openssl::pkey::PKey;
use openssl::pkey::Private;
use base64;
use std::fs::File;
use std::io::{Error, Read};
extern crate gtk;

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
        let encryption = Encryption{};
        match file_input.filename() {
            Some(private_key_path) => {
                let private_key = read_private_key(private_key_path.to_str().unwrap()).unwrap();
                let private_key_pem = private_key.private_key_to_pem_pkcs8().unwrap();
                let private_key_pem_str = match std::str::from_utf8(&private_key_pem) {
                    Ok(v) => v,
                    Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
                };
                let encrypted_data = text_input.text();
                let encrypted_data_str = encrypted_data.as_str();
                match encryption.decrypt(encrypted_data_str, &private_key_pem_str) {
                    Ok(decrypted_data) => {
                        let decrypted_data_string = String::from_utf8(decrypted_data).expect("Data is not a valid utf8 string");
                        let decrypted_data_string = decrypted_data_string.trim_matches(char::from(0));
                        // Update the text input with the decrypted data
                        text_input.set_text(&decrypted_data_string);
                    },
                    Err(_e) => {
                        // Handle the error
                        text_input.set_text("<unable to decrypt>");
                    }
                }
            }
            None => {
                text_input.set_text("<please select key file>");
            }
        }
    });
    

    gtk::main();
}

fn read_private_key(path: &str) -> Result<PKey<Private>, Error> {
    let mut file = File::open(path)?;
    let mut private_key = String::new();
    file.read_to_string(&mut private_key)?;

    let pkey = PKey::private_key_from_pem(private_key.as_bytes())?;
    Ok(pkey)
}

pub struct Encryption;

impl Encryption {
    pub fn decrypt(&self, data: &str, private_key: &str) -> Result<Vec<u8>, openssl::error::ErrorStack> {
        let trimmed_data = data.trim();
        let decoded_data = match base64::decode(trimmed_data) {
            Ok(v) => v,
            Err(_) => "".as_bytes().to_vec(),
        };
        let private_key = PKey::private_key_from_pem(private_key.as_bytes())?.rsa()?;
        let mut decrypted_data = vec![0; private_key.size() as usize];
        private_key.private_decrypt(&decoded_data, &mut decrypted_data, openssl::rsa::Padding::PKCS1)?;
        Ok(decrypted_data)
    }
}
fn main() {
    build_gui();
}