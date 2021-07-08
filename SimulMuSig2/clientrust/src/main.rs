//Protocole de signature MuSig2 avant correction 2021
// use k256::elliptic_curve::group::ff::PrimeField;
// use k256::elliptic_curve::sec1::FromEncodedPoint;
// use k256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar, ScalarBytes};

// use std::convert::TryFrom;
// use std::io::{stdin, Read, Write};
// use std::net::TcpStream;
// use std::ops::{Add, Mul};

// use crypto::digest::Digest;
// use crypto::sha2::Sha256;

fn main() {
    let mut s = clientrust::Signer::new();

    let bytes_vec = clientrust::point_to_bytes(s.public_key);
    let bytes = bytes_vec.as_slice();

    // println!("Faisons des tests :");
    // //On envoie le générateur
    // println!("test : {:?}", ProjectivePoint::generator());
    // clientrust::connect_and_send(clientrust::point_to_bytes(ProjectivePoint::generator()).as_slice());

    // // on envoie un message simple
    // let mes = clientrust::MessageSign::new(ProjectivePoint::generator(), Scalar::from(1_u32));
    // clientrust::connect_and_send(mes.to_bytes().as_slice());

    // // on envoie un hash simple

    // //on construit le hash
    // let mut hash = Sha256::new();
    // let mut bytes: Vec<u8> = Vec::new();
    // bytes.extend(1_u32.to_be_bytes());
    // bytes.extend(clientrust::point_to_bytes_4hash(ProjectivePoint::generator()));
    // bytes.extend(clientrust::M.bytes());
    // hash.input(bytes.as_slice());
    // let mut b: [u8; 32] = [0; 32];
    // hash.result(&mut b);
    // // let mut c = Scalar::from(0_u32);
    // // match ScalarBytes::try_from(&b[..]) {
    // //     Ok(b_scal) => match Scalar::from_repr(b_scal.into_bytes()) {
    // //         Some(x) => c = x,
    // //         None => eprintln!("Erreur "),
    // //     },
    // //     Err(e) => eprintln!("Erreur : {:?}", e),
    // // }
    // println!("le hash vaut : {:?}", b);

    // let mut buffer: Vec<u8> = Vec::new();
    // clientrust::connect_and_receive(&mut buffer);
    // println!("on a reçu : {:?}", buffer);

    // println!("avant le hash rust : {:?}", bytes);
    // let mut buffer: Vec<u8> = Vec::new();
    // clientrust::connect_and_receive(&mut buffer);
    // println!("on a reçu : {:?}", buffer);

    println!("Première étape : communiquer la clé publique, Voulez vous continuer ?");
    if !clientrust::input_yes_no() {
        return;
    }

    clientrust::connect_and_send(bytes);

    println!("Deuxième étape : recevoir les clefs publiques des autres participants, Voulez vous continuer ?");
    if !clientrust::input_yes_no() {
        return;
    }

    let mut buffer: Vec<u8> = Vec::new();
    clientrust::connect_and_receive(&mut buffer);
    s.pubkeys = clientrust::bytes_to_list(&buffer); // nous avons bien reçu les clefs publiques

    println!("Troisième étape : envoyer les nonces autres participants, Voulez vous continuer ?");
    if !clientrust::input_yes_no() {
        return;
    }

    //génération nonces privés
    s.gen_r();
    for i in 0..clientrust::NB_NONCES {
        let mes = clientrust::MessagePoint::new(s.public_key, s.public_nonces[i as usize]);
        let bytes_vec = mes.to_bytes();
        let bytes = bytes_vec.as_slice();
        clientrust::connect_and_send(bytes);
    }

    println!(
        "Quatrième étape : recevoir les nonces des autres participants, Voulez vous continuer ?"
    );
    if !clientrust::input_yes_no() {
        return;
    }

    let mut buffer: Vec<u8> = Vec::new();
    clientrust::connect_and_receive(&mut buffer);
    s.nonces = clientrust::bytes_to_mat(&buffer);

    //calcul local de la signature partielle
    //1 Calcul individuel des ai/Xtilde
    let a = s.a();
    s.a = a;

    let xtilde = s.xtilde();
    s.xtilde = xtilde;

    //2 on calcule les Rj pour j entre 1 et v

    let r_nonces = s.r_nonces();
    s.r_nonces = r_nonces;

    //3 on calcule le vecteur b (ATTENTION CHANGE DANS NOUVELLES VERSION MUSIG2)

    let b = s.b();
    s.b = b;

    //4 on calcule R
    let rsign = s.rsign();
    s.rsign = rsign;

    //5 on calcule c
    let c = s.c();
    s.c = c;

    //6 on calcule s
    let selfsign = s.selfsign();
    s.selfsign = selfsign;

    println!("Sixième étape : envoyer la signature partielle, Voulez vous continuer ?");
    if !clientrust::input_yes_no() {
        return;
    }

    let mes = clientrust::MessageSign::new(s.public_key, s.selfsign);
    let bytes_vec = mes.to_bytes();
    let bytes = bytes_vec.as_slice();
    clientrust::connect_and_send(bytes);

    println!("Septième étape : recevoir les signatures partielles des autres participants, Voulez vous continuer ?");
    if !clientrust::input_yes_no() {
        return;
    }

    let mut buffer: Vec<u8> = Vec::new();
    clientrust::connect_and_receive(&mut buffer);
    s.sign = clientrust::bytes_to_list_scalar(&buffer); // nous avons bien reçu les clefs publiques
    println!("On passe maintenant à la vérification : {}", s.verif());

    // clientrust::connect_and_send(clientrust::point_to_bytes(s.xtilde).as_slice());
    // clientrust::connect_and_send(clientrust::point_to_bytes(s.rsign).as_slice());
    // clientrust::connect_and_send(clientrust::MessageSign::new(s.public_key, signature).to_bytes().as_slice());
}
