//Protocole de signature MuSig2 avant correction 2021

fn main() {
    let mut s = clientrust::Signer::new();

    let bytes_vec = clientrust::point_to_bytes(s.public_key);
    let bytes = bytes_vec.as_slice();

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
}
