use k256::ProjectivePoint;
use k256::EncodedPoint;
use k256::elliptic_curve::group::GroupEncoding;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use clientrust;

fn main() {
    // let stdout = std::io::stdout();
    // let mut io = stdout.lock();
    // let mut buffer = String::new();
    let s = clientrust::Signer::new();

    let bytes_vec = clientrust::point_to_bytes(s.public_key);
    let bytes = bytes_vec.as_slice();

    println!("Première étape communiquer la clé publique, Voulez vous continuer ?");
    if !clientrust::input_yes_no() {
        return;
    }

    clientrust::connect_and_send(bytes);

    println!("Deuxième étape recevoir les clefs publiques des autres participants, Voulez vous continuer ?");
    if !clientrust::input_yes_no() {
        return;
    }

    let mut buffer: Vec<u8>  = Vec::new();
    clientrust::connect_and_receive(&mut buffer);
    let pubkeys = clientrust::bytes_to_list(&buffer);

}