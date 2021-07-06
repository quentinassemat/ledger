use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::elliptic_curve::group::ff::PrimeField;
use k256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar, ScalarBytes};

use std::convert::TryFrom;
use std::io::{stdin, Read, Write};
use std::net::TcpStream;
use std::ops::Mul;

use crypto::digest::Digest;
use crypto::sha2::Sha256;


// CONSTANTES UTILES

pub const ADRESSE: &str = "localhost";
pub const PORT: u16 = 1234;
pub const NB_NONCES: u32 = 3;
pub const NB_PARTICIPANT: u32 = 6;
pub const MEM: usize = 16496;

// STRUCTURE DE DONNÉES

// Struct simulant un signeur comme dans tools.py
pub struct Signer {
    // éléments publiques
    pub public_key: ProjectivePoint,
    pub public_nonces: Vec<ProjectivePoint>,
    pub pubkeys: Vec<ProjectivePoint>,
    pub nonces: Vec<Vec<ProjectivePoint>>,

    //éléments secrets
    secret_key: Scalar,
    secret_list_r: Vec<Scalar>,
}

impl Signer {
    // constructeur
    pub fn new() -> Signer {
        let gen = ProjectivePoint::generator();
        let secret_key = Scalar::generate_biased(rand::thread_rng()); // ou generate_vartime ? mais side channels ?
        let public_key = gen.mul(secret_key);
        let secret_list_r: Vec<Scalar> = Vec::new();
        let public_nonces: Vec<ProjectivePoint> = Vec::new();
        let pubkeys: Vec<ProjectivePoint> = Vec::new();
        let nonces: Vec<Vec<ProjectivePoint>> = Vec::new();

        Signer {
            public_key,
            secret_key,
            secret_list_r,
            public_nonces,
            pubkeys,
            nonces,
        }
    }

    //fonction de génération des nonces privées
    pub fn gen_r(&mut self) {
        self.secret_list_r.clear();
        for _i in 0..NB_NONCES {
            self.secret_list_r
                .push(Scalar::generate_biased(rand::thread_rng()));
            self.public_nonces
                .push(ProjectivePoint::generator().mul(self.secret_key));
        }
    }

    //fonction calcul des ai
    pub fn a(&self) -> Vec<Scalar> {
        let mut a: Vec<Scalar> = Vec::new();
        for i in 0..NB_PARTICIPANT {
            let mut hash = Sha256::new();

            //on construit les bytes qui servent pour la hash
            let mut bytes: Vec<u8> = Vec::new();
            for j in 0..NB_PARTICIPANT {
                let affine_p = AffinePoint::from(self.pubkeys[j as usize]);
                let encoded_p = EncodedPoint::from(affine_p);
                match encoded_p.x() {
                    Some(x) => bytes.extend(x),
                    None => eprintln!("Erreur"),
                }
            }
            let affine_p = AffinePoint::from(self.pubkeys[i as usize]);
            let encoded_p = EncodedPoint::from(affine_p);
            match encoded_p.x() {
                Some(x) => bytes.extend(x),
                None => eprintln!("Erreur"),
            }

            //on le met dans le hash
            hash.input(bytes.as_slice());
            let mut ai: [u8; 32] = [0; 32];
            hash.result(&mut ai);

            //On construit le Scalar qui corrrespond
            match ScalarBytes::try_from(&ai[..]) {
                Ok(ai_scal) => match Scalar::from_repr(ai_scal.into_bytes()) {
                    Some(x) => a.push(x),
                    None => eprintln!("Erreur "),
                },
                Err(e) => eprintln!("Erreur : {:?}", e),
            }
        }
        a
    }
}

impl Default for Signer {
    fn default() -> Self {
        Self::new()
    }
}

pub struct MessagePoint {
    pub id: ProjectivePoint,
    pub point: ProjectivePoint,
}

impl MessagePoint {
    // constructeur
    pub fn new(id: ProjectivePoint, point: ProjectivePoint) -> MessagePoint {
        MessagePoint { id, point }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut res: Vec<u8> = Vec::new();
        let id = "[ID :".as_bytes();
        let crochet = " ] ".as_bytes();
        res.extend(id.iter());
        res.extend(point_to_bytes(self.id));
        res.extend(crochet.iter());
        res.extend(point_to_bytes(self.point));
        res
    }
}

// FONCTIONS DE CONVERSION BYTES -- TYPES

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
        } else {
            // correspond au point à l'infini d'après la doc
            return b"(0x0 : 0x1 : 0x0)".to_vec();
        }
    } else {
        return b"(0x0 : 0x1 : 0x0)".to_vec();
    }
    res
}

pub fn bytes_to_point(bytes: &[u8]) -> ProjectivePoint {
    let l = bytes.len();
    let mut i = 1;
    let mut count = 0;
    let mut x: k256::ScalarBytes = k256::ScalarBytes::default();
    let mut y: k256::ScalarBytes = k256::ScalarBytes::default();
    let mut x_bits: Vec<u8> = Vec::new();
    let mut y_bits: Vec<u8> = Vec::new();
    let mut z_bits: Vec<u8> = Vec::new();
    while i < l - 3 {
        if count == 0 {
            while (i < l - 3) && (bytes[i] != b' ' || bytes[i + 1] != b':' || bytes[i + 2] != b' ')
            {
                x_bits.push(bytes[i]);
                i += 1;
            }
            count += 1;
            i += 3;
        }
        if count == 1 {
            while (i < l - 3) && (bytes[i] != b' ' || bytes[i + 1] != b':' || bytes[i + 2] != b' ')
            {
                y_bits.push(bytes[i]);
                i += 1;
            }
            count += 1;
            i += 3;
        }
        if count == 2 {
            while i < l - 3 && bytes[i - 1] != b')' {
                z_bits.push(bytes[i]);
                i += 1;
            }
        } else {
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

pub fn bytes_to_messagepoint(bytes: &[u8]) -> MessagePoint {
    let mut i = 0;
    let l = bytes.len();
    while i < l - 3 && (bytes[i] != b' ' || bytes[i + 1] != b']' || bytes[i + 2] != b' ') {
        i += 1;
    }
    let id = bytes_to_point(&bytes[5..i]);
    let point = bytes_to_point(&bytes[i + 3..]);
    MessagePoint { id, point }
}

pub fn bytes_to_list(bytes: &[u8]) -> Vec<ProjectivePoint> {
    let mut res: Vec<ProjectivePoint> = Vec::new();
    let l = bytes.len();
    let mut i = 0;
    let mut old_i = 0;
    while i < l - 3 {
        while i < l - 3 && (bytes[i] != b' ' || bytes[i + 1] != b';' || bytes[i + 2] != b' ') {
            i += 1;
        }
        res.push(bytes_to_point(&bytes[old_i..i]));
        i += 3;
        old_i = i;
    }
    res
}

pub fn bytes_to_mat(bytes: &[u8]) -> Vec<Vec<ProjectivePoint>> {
    // Vec[i][j] est le nonce j du signeur i
    let mut res: Vec<Vec<ProjectivePoint>> = Vec::new();
    let l = bytes.len();
    let mut i = 0;
    let mut old_i = 0;
    while i < l - 3 {
        while i < l - 3 && (bytes[i] != b' ' || bytes[i + 1] != b'\n' || bytes[i + 2] != b' ') {
            i += 1;
        }
        res.push(bytes_to_list(&bytes[old_i..i]));
        i += 3;
        old_i = i;
    }
    res
}

// GÉRER LES ENTRÉES AU CLAVIER
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
        _ => return Err("Please enter a valide input (yes/no)"),
    }
}

pub fn input_yes_no() -> bool {
    loop {
        match yes_no() {
            Err(s) => println!("{:?}", s),
            Ok(x) => {
                return x;
            }
        }
    }
}

// FONCTIONS RÉSEAUX
pub fn connect_and_send(bytes: &[u8]) {
    match TcpStream::connect((ADRESSE, PORT)) {
        Ok(mut stream) => {
            println!("Connecté");
            if let Err(error) = stream.write(bytes) {
                //write!(stream, "{}\n", b"test")
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

pub fn connect_and_receive(buffer: &mut Vec<u8>) {
    match TcpStream::connect((ADRESSE, PORT)) {
        Ok(mut stream) => {
            println!("Connecté");
            if let Err(error) = stream.read_to_end(buffer) {
                //write!(stream, "{}\n", b"test")
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
