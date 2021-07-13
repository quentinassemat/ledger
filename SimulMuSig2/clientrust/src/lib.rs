#![warn(clippy::many_single_char_names)]

use k256::elliptic_curve::group::ff::PrimeField;
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar, ScalarBytes};

use std::convert::TryFrom;
use std::io::{stdin, Read, Write};
use std::net::TcpStream;

use crypto::digest::Digest;
use crypto::sha2::Sha256;

// CONSTANTES UTILES

pub const ADRESSE: &str = "localhost";
pub const PORT: u16 = 1234;

pub const NB_NONCES: u32 = 3;
pub const NB_PARTICIPANT: u32 = 6;
pub const MEM: usize = 16496;

pub const M: &str = "Alice donne 1 Bitcoin à Bob";

// STRUCTURE DE DONNÉES

// Struct simulant un signeur comme dans tools.py
pub struct Signer {
    // éléments publiques
    pub public_key: ProjectivePoint,
    pub public_nonces: Vec<ProjectivePoint>,
    pub pubkeys: Vec<ProjectivePoint>,
    pub nonces: Vec<Vec<ProjectivePoint>>,
    pub a: Vec<Scalar>,
    pub selfa: Scalar,
    pub xtilde: ProjectivePoint,
    pub r_nonces: Vec<ProjectivePoint>,
    pub b: Vec<Scalar>,
    pub rsign: ProjectivePoint,
    pub c: Scalar,
    pub selfsign: Scalar,
    pub sign: Vec<Scalar>,

    //éléments secrets
    secret_key: Scalar,
    secret_list_r: Vec<Scalar>,
}

impl Signer {
    // constructeur
    pub fn new() -> Signer {
        let secret_key = Scalar::generate_biased(rand::thread_rng()); // ou generate_vartime ? mais side channels ?
        let public_key = ProjectivePoint::generator() * secret_key;
        let secret_list_r: Vec<Scalar> = Vec::new();
        let public_nonces: Vec<ProjectivePoint> = Vec::new();
        let pubkeys: Vec<ProjectivePoint> = Vec::new();
        let nonces: Vec<Vec<ProjectivePoint>> = Vec::new();
        let a: Vec<Scalar> = Vec::new();
        let selfa = Scalar::default();
        let xtilde = ProjectivePoint::default();
        let r_nonces: Vec<ProjectivePoint> = Vec::new();
        let b: Vec<Scalar> = Vec::new();
        let rsign = ProjectivePoint::default();
        let c = Scalar::default();
        let selfsign = Scalar::default();
        let sign: Vec<Scalar> = Vec::new();

        Signer {
            public_key,
            public_nonces,
            pubkeys,
            nonces,
            a,
            selfa,
            xtilde,
            r_nonces,
            b,
            rsign,
            c,
            selfsign,
            sign,
            secret_key,
            secret_list_r,
        }
    }

    //fonction de génération des nonces privées
    pub fn gen_r(&mut self) {
        self.secret_list_r.clear();
        self.public_nonces.clear();
        for i in 0..NB_NONCES {
            self.secret_list_r
                .push(Scalar::generate_biased(rand::thread_rng()));
            // self.secret_list_r
            //     .push(Scalar::from(1_u32));
            self.public_nonces
                .push(ProjectivePoint::generator() * self.secret_list_r[i as usize]);
        }
    }

    //FONCTIONS DE CALCUL DU SIGNEUR

    //fonction calcul des ai
    pub fn a(&mut self) -> Vec<Scalar> {
        let mut a: Vec<Scalar> = Vec::new();
        for i in 0..NB_PARTICIPANT {
            let mut hash = Sha256::new();

            //on construit les bytes qui servent pour la hash
            let mut bytes: Vec<u8> = Vec::new();
            for j in 0..NB_PARTICIPANT {
                bytes.extend(point_to_bytes_4hash(self.pubkeys[j as usize]));
            }
            bytes.extend(point_to_bytes_4hash(self.pubkeys[i as usize]));

            //on le met dans le hash
            hash.input(bytes.as_slice());
            let mut ai: [u8; 32] = [0; 32];
            hash.result(&mut ai);

            //On construit le Scalar qui corrrespond
            match ScalarBytes::try_from(&ai[..]) {
                Ok(ai_scal) => match Scalar::from_repr(ai_scal.into_bytes()) {
                    Some(x) => {
                        a.push(x);
                        if self.pubkeys[i as usize] == self.public_key {
                            self.selfa = x;
                        }
                    }
                    None => eprintln!("Erreur "),
                },
                Err(e) => eprintln!("Erreur : {:?}", e),
            }
        }
        a
    }

    //fonction de calcul de x_tilde :
    pub fn xtilde(&self) -> ProjectivePoint {
        let mut xtilde = ProjectivePoint::identity();
        for i in 0..NB_PARTICIPANT {
            xtilde = xtilde + (self.pubkeys[i as usize] * self.a[i as usize]);
        }
        xtilde
    }

    //fonction de calcul de r_nonces :
    pub fn r_nonces(&self) -> Vec<ProjectivePoint> {
        let mut r_nonces: Vec<ProjectivePoint> = Vec::new();
        for j in 0..NB_NONCES {
            let mut temp = ProjectivePoint::identity();
            for i in 0..NB_PARTICIPANT {
                temp = temp + self.nonces[i as usize][j as usize];
            }
            r_nonces.push(temp);
        }
        r_nonces
    }

    //fonction de calcul de b :
    pub fn b(&self) -> Vec<Scalar> {
        let mut b: Vec<Scalar> = Vec::new();
        b.push(Scalar::one());
        for j in 1..NB_NONCES {
            let mut hash = Sha256::new();

            //on construit les bytes qui servent pour le hash
            let mut bytes: Vec<u8> = Vec::new();
            bytes.extend(j.to_be_bytes());
            bytes.extend(point_to_bytes_4hash(self.xtilde));
            for j in 0..NB_NONCES {
                bytes.extend(point_to_bytes_4hash(self.r_nonces[j as usize]));
            }
            bytes.extend(M.bytes());

            //on le met dans le hash
            hash.input(bytes.as_slice());
            let mut bi: [u8; 32] = [0; 32];
            hash.result(&mut bi);

            //On construit le Scalar qui corrrespond
            match ScalarBytes::try_from(&bi[..]) {
                Ok(bi_scal) => match Scalar::from_repr(bi_scal.into_bytes()) {
                    Some(x) => b.push(x),
                    None => eprintln!("Erreur "),
                },
                Err(e) => eprintln!("Erreur : {:?}", e),
            }
        }
        b
    }

    //fonction de calcul de R:
    pub fn rsign(&self) -> ProjectivePoint {
        let mut rsign = ProjectivePoint::identity();
        for j in 0..NB_NONCES {
            rsign = rsign + (self.r_nonces[j as usize] * self.b[j as usize]);
        }
        rsign
    }

    //fonction de calcul de c:
    pub fn c(&self) -> Scalar {
        let mut hash = Sha256::new();
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend(point_to_bytes_4hash(self.xtilde));
        bytes.extend(point_to_bytes_4hash(self.rsign));
        bytes.extend(M.bytes());
        hash.input(bytes.as_slice());
        let mut b: [u8; 32] = [0; 32];
        hash.result(&mut b);
        let mut c = Scalar::zero();
        match ScalarBytes::try_from(&b[..]) {
            Ok(b_scal) => match Scalar::from_repr(b_scal.into_bytes()) {
                Some(x) => c = x,
                None => eprintln!("Erreur "),
            },
            Err(e) => eprintln!("Erreur : {:?}", e),
        }
        c
    }

    //fonction de calcul de sign :
    pub fn selfsign(&self) -> Scalar {
        let mut temp = Scalar::zero();
        for j in 0..NB_NONCES {
            temp = temp + (self.secret_list_r[j as usize] * self.b[j as usize]);
        }
        (self.c * self.selfa * self.secret_key) + temp
    }

    pub fn signature(&self) -> Scalar {
        let mut signature = Scalar::zero();
        for i in 0..NB_PARTICIPANT {
            signature = signature + self.sign[i as usize];
        }
        println!("signature : {:?}", signature);
        signature
    }

    //fonction de vérif :
    pub fn verif(&self) -> bool {
        let signature = self.signature();
        AffinePoint::from(ProjectivePoint::generator() * signature)
            == AffinePoint::from(self.rsign + (self.xtilde * self.c))
    }

    //fonction de debug
    pub fn affich(&self) {
        println!("on va afficher tout les paramètres pour voir s'il y a un truc qui va pas");
        println!("public_key : {:?}", AffinePoint::from(self.public_key));
        println!("public_nonces : {:?}", self.public_nonces);
        println!("pubkeys : {:?}", self.pubkeys);
        println!("nonces : {:?}", self.nonces);
        println!("a: {:?}", self.a);
        println!("selfa : {:?}", self.selfa);
        println!("xtilde : {:?}", self.xtilde);
        println!("r_nonces : {:?}", self.r_nonces);
        println!("b : {:?}", self.b);
        println!("rsign : {:?}", self.rsign);
        println!("c : {:?}", self.c);
        println!("selfsign : {:?}", self.selfsign);
        println!("sign : {:?}", self.sign);
        println!("secret_key : {:?}", self.secret_key);
        println!("secret_list_r : {:?}", self.secret_list_r);
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

pub struct MessageSign {
    pub id: ProjectivePoint,
    pub sign: Scalar,
}

impl MessageSign {
    // constructeur
    pub fn new(id: ProjectivePoint, sign: Scalar) -> MessageSign {
        MessageSign { id, sign }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut res: Vec<u8> = Vec::new();
        let id = "[ID :".as_bytes();
        let crochet = " ] ".as_bytes();
        res.extend(id.iter());
        res.extend(point_to_bytes(self.id));
        res.extend(crochet.iter());
        res.extend(self.sign.to_bytes().as_slice());
        res
    }
}

// FONCTIONS DE CONVERSION BYTES -- TYPES

pub fn point_to_bytes(p: ProjectivePoint) -> Vec<u8> {
    let mut res: Vec<u8> = Vec::new();
    let par = "(".as_bytes();
    let deuxpoints = " : ".as_bytes();
    let parend = ")".as_bytes();
    res.extend(par);
    let affine_p = AffinePoint::from(p);
    let encoded_p = EncodedPoint::encode(affine_p, false);
    if let Some(x) = encoded_p.x() {
        if let Some(y) = encoded_p.y() {
            res.append(&mut x.to_vec());
            res.extend(deuxpoints);
            res.append(&mut y.to_vec());
            res.extend_from_slice(parend);
        } else {
            // à corriger
            // correspond au point à l'infini d'après la doc
            res.extend("(0x0 : 0x1 : 0x0)".as_bytes());
        }
    } else {
        // à corriger
        res.extend("(0x0 : 0x1 : 0x0)".as_bytes());
    }
    res
}

pub fn point_to_bytes_4hash(p: ProjectivePoint) -> Vec<u8> {
    let mut res: Vec<u8> = Vec::new();
    let a = AffinePoint::from(p);
    let e = EncodedPoint::from(a);
    match e.x() {
        Some(y) => {
            res.extend(y.iter());
            res
        }
        None => {
            eprintln!("Erreur de conversion");
            res
        }
    }
}

pub fn bytes_to_point(bytes: &[u8]) -> ProjectivePoint {
    let len = bytes.len();
    let mut i = 1;
    let mut x: k256::ScalarBytes = k256::ScalarBytes::default();
    let mut y: k256::ScalarBytes = k256::ScalarBytes::default();
    let mut x_bits: Vec<u8> = Vec::new();
    let mut y_bits: Vec<u8> = Vec::new();
    while (i < len) && (bytes[i] != b' ' || bytes[i + 1] != b':' || bytes[i + 2] != b' ') {
        x_bits.push(bytes[i]);
        i += 1;
    }
    y_bits.extend_from_slice(&bytes[i + 3..len - 1]);
    match k256::ScalarBytes::try_from(x_bits.as_slice()) {
        Err(e) => eprintln!("Erreur1 : {}", e),
        Ok(a) => x = a,
    }
    match k256::ScalarBytes::try_from(y_bits.as_slice()) {
        Err(e) => eprintln!("Erreur2 : {}", e),
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
    while i < l {
        while (i < l) && (bytes[i] != b' ' || bytes[i + 1] != b';' || bytes[i + 2] != b' ') {
            i += 1;
        }
        res.push(bytes_to_point(&bytes[old_i..i]));
        i += 3;
        old_i = i;
    }
    res
}

pub fn bytes_to_list_scalar(bytes: &[u8]) -> Vec<Scalar> {
    let mut res: Vec<Scalar> = Vec::new();
    let l = bytes.len();
    let mut i = 0;
    let mut old_i = 0;
    while i < l {
        while (i < l) && (bytes[i] != b' ' || bytes[i + 1] != b';' || bytes[i + 2] != b' ') {
            i += 1;
        }
        match ScalarBytes::try_from(&bytes[old_i..i]) {
            Ok(x) => res.push(x.to_scalar()),
            Err(e) => eprintln!("Erreur : {}", e),
        }
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
    while i < l {
        while (i < l) && (bytes[i] != b' ' || bytes[i + 1] != b'\n' || bytes[i + 2] != b' ') {
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
        "yes" => Ok(true),
        "no" => Ok(false),
        _ => Err("Please enter a valide input (yes/no)"),
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
