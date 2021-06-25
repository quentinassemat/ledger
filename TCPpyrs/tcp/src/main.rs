use std::net::TcpStream;
use std::io::{Write, Read, stdin, stdout};

fn get_entry() -> String {
    let mut buf = String::new();

    stdin().read_line(&mut buf);
    buf.replace("\n", "").replace("\r", "")
}

fn exchange_with_server(mut stream: TcpStream) -> bool {
    let stdout = std::io::stdout();
    let mut io = stdout.lock();
    let mut buffer = String::new();

    println!("Enter your message or 'quit' when you want to leave");
    
    write!(io, "> ");
    // pour afficher de suite
    io.flush();
    match &*get_entry() {
        "quit" => {
            println!("bye !");
            write!(stream, "{}\n", "quit");
            return true;
        }
        line => {
            write!(stream, "{}\n", line);
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
            write!(io,"{}" ,buffer);
        }
    }
    false
}

fn main() {
    println!("Tentative de connexion au serveur...");
    loop {
        match TcpStream::connect(("localhost", 1234)) {
            Ok(stream) => {
                if exchange_with_server(stream) {
                    return;
                }
            }
            Err(e) => {
                println!("La connexion au serveur a échoué : {}", e);
            }
        }
    }
}