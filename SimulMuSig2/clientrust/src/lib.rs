// use std::net::TcpStream; à remettre si on met des fonctions send_connect/send_receive
use std::io::{Write, stdin, Read};
use k256::{ProjectivePoint, Scalar, FieldBytes, ScalarBytes, CompressedPoint, EncodedPoint};
use sha2::Sha256;
use std::ops::Mul;
use std::net::TcpStream;
use std::convert::TryFrom;
use k256::elliptic_curve::sec1::FromEncodedPoint;

pub const ADRESSE : &str  = "localhost";
pub const PORT : u16= 1234;
pub const NB_NONCES: u32 = 3;
pub const MEM: usize = 16496;

pub struct Signer {
    pub public_key: ProjectivePoint, 
    secret_key: Scalar,
    pub list_r: Vec<Scalar>
}

// de ce que je comprend du crate nous allons utiliser les différents types de la manières suivante
// ProjectivePoint pour les éléments de la courbe elliptique (les opérations sont codés)
// Scalar pour représenter les gros entiers modulo l'ordre de la courbe
// CompressedPoint pour transmettre au serveur les éléments de la courbe
// FieldBytes pour transmettre au serveur les gros entiers modulo l'ordre de la courbe

impl Signer {
    // constructeur 
    pub fn new() -> Signer {
        let gen = ProjectivePoint::generator();
        let secret_key = Scalar::generate_biased(rand::thread_rng()); // ou generate_vartime ? mais side channels ?
        let public_key = gen.mul(secret_key);
        let list_r : Vec<Scalar> = Vec::new();

        Signer {
            public_key,
            secret_key,
            list_r,
        }
    }

    //fonction de génération des nonces privées
    pub fn gen_r(&mut self) {
        self.list_r.clear();
        for _i in 0..NB_NONCES {
            self.list_r.push(Scalar::generate_biased(rand::thread_rng()));
        }
    }
}

impl Default for Signer {
    fn default() -> Self {
        Self::new()
    }
}

// pour gérer les entrées clavier 
pub fn get_entry() -> String {
    let mut buf = String::new();

    match stdin().read_line(&mut buf) {
        Ok(n) => {
            println!("{} bytes read", n);
        }
        Err(error) => eprintln!("error: {}", error),
    }
    buf.replace("\n", "").replace("\r", "")
}

// fonction yes_no() pour que l'utilisateur dise oui ou non à chaque étape 
pub fn yes_no() -> Result<bool, &'static str> {
    match &*get_entry() {
        "yes" => return Ok(true),
        "no" => return Ok(false),
        _ => return Err("Please enter a valide input (yes/no)")
    }
}

pub fn input_yes_no() -> bool {
    loop {
        match yes_no() {
            Err(s) => println!("{:?}",s),
            Ok(x) => {
                return x;
            }
        }
    }
}

pub fn point_to_bytes(p: ProjectivePoint) -> Vec<u8> {
    let mut res: Vec<u8> = Vec::new();
    res.push(b'(');
    let encoded_p = k256::EncodedPoint::encode(p, false);
    encoded_p.is_identity();
    if let Some(x) = encoded_p.x() {
        if let Some(y) = encoded_p.y() {
            res.append(&mut x.to_vec());
            res.push(b' ');
            res.push(b':');
            res.push(b' ');
            res.append(&mut y.to_vec());
            res.push(b' ');
            res.push(b':');
            res.push(b' ');
            res.push(b'0');
            res.push(b'x');
            res.push(b'1');
            res.push(b')');
        } else { // correspond au point à l'infini d'après la doc
            return b"(0x0 : 0x1 : 0x0)".to_vec();
        }
    } else {
        return b"(0x0 : 0x1 : 0x0)".to_vec();
    }
    res
}

pub fn bytes_to_point(bytes : &[u8]) -> ProjectivePoint {
    let l = bytes.len();
    let mut i = 1;
    let mut count = 0;
    let mut x: k256::ScalarBytes = k256::ScalarBytes::default();
    let mut y: k256::ScalarBytes = k256::ScalarBytes::default();
    let mut x_bits : Vec<u8> = Vec::new();
    let mut y_bits : Vec<u8> = Vec::new();
    let mut z_bits : Vec<u8> = Vec::new();
    while i < l - 3 {
        if count == 0 {
            while (i < l - 3) && ( bytes[i] != b' ' || bytes[i+1] != b':' || bytes[i+2] != b' ' ) {
                x_bits.push(bytes[i]);
                i += 1;
            }
            count += 1;
            i += 3;
        }
        if count == 1 {
            while (i < l - 3) && ( bytes[i] != b' ' || bytes[i+1] != b':' || bytes[i+2] != b' ' ) {
                y_bits.push(bytes[i]);
                i += 1;
            }
            count += 1;
            i += 3;
        }
        if count == 2 {
            while i < l - 3 && bytes[i-1] != b')' {
                z_bits.push(bytes[i]);
                i += 1;
            }
        } 
        else {
            break;
        }
    }
    match k256::ScalarBytes::try_from(x_bits.as_slice()) {
        Err(e) => eprintln!("Erreur : {}", e),
        Ok(a) => x = a,
    }
    match k256::ScalarBytes::try_from(y_bits.as_slice()) {
        Err(e) => eprintln!("Erreur : {}", e),
        Ok(a) => y = a,
    }
    let encoded_p = EncodedPoint::from_affine_coordinates(&x.into_bytes(), &y.into_bytes(), false);
    match ProjectivePoint::from_encoded_point(&encoded_p) {
        Some(p) => p,
        None => ProjectivePoint::generator(),
    }
}

pub fn bytes_to_list(bytes : &[u8]) -> Vec<ProjectivePoint> {
    let mut res : Vec<ProjectivePoint> = Vec::new();
    let l = bytes.len();
    let mut i = 0;
    let mut old_i = 0;
    while i < l - 3 {
        while i < l - 3 && ( bytes[i] != b' ' || bytes[i+1] != b';' || bytes[i+2] != b' ' ) {
            i += 1;
        }
        res.push(bytes_to_point(&bytes[old_i..i]));
        i += 3;
        old_i = i;
    }
    res
}

pub fn connect_and_send(bytes: &[u8]) {
    match TcpStream::connect((ADRESSE, PORT)) {
        Ok(mut stream) => {
            println!("Connecté");
            if let Err(error) = stream.write(bytes) { //write!(stream, "{}\n", b"test")
                eprintln!("error: {}", error);
            };
            if let Err(error) = stream.flush() {
                eprintln!("error: {}", error);
            }
            println!("Bytes sent");
        }
        Err(e) => {
            eprintln!("La connexion au serveur a échoué : {}", e);
        }
    }
}

pub fn connect_and_receive(buffer : &mut Vec<u8>) {
    match TcpStream::connect((ADRESSE, PORT)) {
        Ok(mut stream) => {
            println!("Connecté");
            if let Err(error) = stream.read_to_end(buffer) { //write!(stream, "{}\n", b"test")
                eprintln!("error: {}", error);
            };
            if let Err(error) = stream.flush() {
                eprintln!("error: {}", error);
            }
            println!("Bytes received");
        }
        Err(e) => {
            eprintln!("La connexion au serveur a échoué : {}", e);
        }
    }
}