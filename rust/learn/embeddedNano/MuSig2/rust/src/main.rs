#![no_std]
#![no_main]

mod crypto_helpers;
mod utils;
mod lib;

use core::str::from_utf8;
use crypto_helpers::*;
use nanos_sdk::buttons::ButtonEvent;
use nanos_sdk::ecc::DerEncodedEcdsaSignature;
use nanos_sdk::io;
use nanos_sdk::io::SyscallError;
use nanos_ui::ui;

nanos_sdk::set_panic!(nanos_sdk::exiting_panic);

/// Display public key in two separate
/// message scrollers
fn show_pubkey() {
    let pubkey = get_pubkey();
    match pubkey {
        Ok(pk) => {
            {
                let hex0 = utils::to_hex(&pk.W[1..33]).unwrap();
                let m = from_utf8(&hex0).unwrap();
                ui::MessageScroller::new(m).event_loop();
            }
            {
                let hex1 = utils::to_hex(&pk.W[33..65]).unwrap();
                let m = from_utf8(&hex1).unwrap();
                ui::MessageScroller::new(m).event_loop();
            }
        }
        Err(_) => ui::popup("Error"),
    }
}

/// Basic nested menu. Will be subject
/// to simplifications in the future.
#[allow(clippy::needless_borrow)]
fn menu_example() {
    let mut s = Signer::new();
    loop {
        match ui::Menu::new(&[&"PubKey", &"Infos", &"Back", &"Exit App"]).show() {
            0 => show_pubkey(),
            1 => loop {
                match ui::Menu::new(&[&"Copyright", &"Authors", &"Back"]).show() {
                    0 => ui::popup("2020 Ledger"),
                    1 => ui::popup("???"),
                    _ => break,
                }
            },
            2 => return,
            3 => nanos_sdk::exit_app(0),
            _ => (),
        }
    }
}

/// This is the UI flow for signing, composed of a scroller
/// to read the incoming message, a panel that requests user
/// validation, and an exit message.
fn sign_ui(message: &[u8]) -> Result<Option<DerEncodedEcdsaSignature>, SyscallError> {
    ui::popup("Message review");

    {
        let hex = utils::to_hex(message).map_err(|_| SyscallError::Overflow)?;
        let m = from_utf8(&hex).map_err(|_| SyscallError::InvalidParameter)?;

        ui::MessageScroller::new(m).event_loop();
    }

    if ui::Validator::new("Sign ?").ask() {
        let k = get_private_key()?;
        let (sig, _sig_len) = detecdsa_sign(message, &k).unwrap();
        ui::popup("Done !");
        Ok(Some(sig))
    } else {
        ui::popup("Cancelled");
        Ok(None)
    }
}

#[no_mangle]
extern "C" fn sample_main() {
    let mut comm = io::Comm::new();

    loop {
        // Draw some 'welcome' screen
        ui::SingleMessage::new("Welcome MuSig2").show();
        // Wait for either a specific button push to exit the app
        // or an APDU command
        match comm.next_event() {
            io::Event::Button(ButtonEvent::RightButtonRelease) => nanos_sdk::exit_app(0),
            io::Event::Command(ins) => match handle_apdu(&mut comm, ins) {
                Ok(()) => comm.reply_ok(),
                Err(sw) => comm.reply(sw),
            },
            _ => (),
        }
    }
}

#[repr(u8)]
enum Ins {
    GetPubkey,
    SendPubkeys,
    GetListPoint,
    SendMatPoint,
    GetSign,
    SendSigns
    Menu,
    ShowPrivateKey,
    Exit,
}

impl From<u8> for Ins {
    fn from(ins: u8) -> Ins {
        match ins {
            1 => Ins::GetPubkey,
            2 => Ins::SendPubkeys,
            3 => Ins::GetListPoint,
            4 => Ins::SendMatPoint,
            5 => Ins::GetSign,
            6 => Ins::SendSigns,
            7 => Ins::Menu
            0xfe => Ins::ShowPrivateKey,
            0xff => Ins::Exit,
            _ => panic!(),
        }
    }
}

use nanos_sdk::io::Reply;

fn handle_apdu(s: Signer, comm: &mut io::Comm, ins: Ins) -> Result<(), Reply> {
    if comm.rx == 0 {
        return Err(io::StatusWords::NothingReceived.into());
    }

    match ins {
        Ins::GetPubkey => comm.append(&get_pubkey()?.W),
        Ins::SendPubkeys => {
            let mut buffer: comm::get_data();
            s.pubkeys = bytes_to_list(&buffer); 
            ui::popup("Received publics keys");
        }
        Ins::Menu => menu_example(),
        Ins::ShowPrivateKey => comm.append(&bip32_derive_secp256k1(&BIP32_PATH)?),
        Ins::Exit => nanos_sdk::exit_app(0),
    }
    Ok(())
}
