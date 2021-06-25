use std::net::TcpStream;
use std::io::{Write, Read, stdin};

fn get_entry() -> String {
    let mut buf = String::new();

    match stdin().read_line(&mut buf) {
        Ok(n) => {
            println!("{} bytes read", n);
        }
        Err(error) => eprintln!("error: {}", error),
    }
    buf.replace("\n", "").replace("\r", "")
}

fn exchange_with_server() -> bool {
    let stdout = std::io::stdout();
    let mut io = stdout.lock();
    let mut buffer = String::new();

    println!("Enter your message or 'quit' when you want to leave");
    
    if let Err(error) = write!(io, "> ") {
        eprintln!("error: {}", error);
    };
    // pour afficher de suite
    if let Err(error) = io.flush() {
        eprintln!("error: {}", error);
    };
    match &*get_entry() {
        "quit" => {
            println!("bye !");
            return true;
        }
        line => {
            match TcpStream::connect(("localhost", 1234)) {
                Ok(mut stream) => {
                    println!("Connecté");
                    if let Err(error) = write!(stream, "{}\n", line) {
                        eprintln!("error: {}", error);
                    };
                    match stream.read_to_string(&mut buffer) {
                        Ok(received) => {
                            if received < 1 {
                                println!("Perte de la connexion avec le serveur");
                                return false;
                            }
                        }
                        Err(_) => {
                            println!("Perte de la connexion avec le serveur");
                            return false;
                        }
                    }
                    println!("Réponse du serveur : ");
                    if let Err(error) = write!(io,"{}" ,buffer) {
                        eprintln!("error: {}", error);
                    };
                }
                Err(e) => {
                    eprintln!("La connexion au serveur a échoué : {}", e);
                }
            }
        }
    }
    false
}

fn main() {
    println!("Tentative de connexion au serveur...");
    loop {
        if exchange_with_server() {
            return;
        }
    }
}