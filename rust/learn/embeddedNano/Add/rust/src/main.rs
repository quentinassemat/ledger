#![no_std]
#![no_main]

mod crypto_helpers;
mod utils;

use core::str::from_utf8;
use crypto_helpers::*;
use nanos_sdk::bindings;
use nanos_sdk::buttons::ButtonEvent;
use nanos_sdk::io;
// use nanos_sdk::io::SyscallError;
use nanos_ui::ui;

pub const N_BYTES: u32 = 32;

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

// fn sign_ui(message: &[u8]) -> Result<Option<DerEncodedEcdsaSignature>, SyscallError> {
//     ui::popup("Message review");

//     {
//         let hex = utils::to_hex(message).map_err(|_| SyscallError::Overflow)?;
//         let m = from_utf8(&hex).map_err(|_| SyscallError::InvalidParameter)?;

//         ui::MessageScroller::new(m).event_loop();
//     }

//     if ui::Validator::new("Sign ?").ask() {
//         let k = get_private_key()?;
//         let (sig, _sig_len) = detecdsa_sign(message, &k).unwrap();
//         ui::popup("Done !");
//         Ok(Some(sig))
//     } else {
//         ui::popup("Cancelled");
//         Ok(None)
//     }
// }

#[no_mangle]
extern "C" fn sample_main() {
    let mut comm = io::Comm::new();
    comm.reply_ok();
    loop {
        // Draw some 'welcome' screen
        ui::SingleMessage::new("Welcome MuSig2").show();
        // Wait for either a specific button push to exit the app
        // or an APDU command

        match comm.next_event() {
            io::Event::Button(ButtonEvent::RightButtonRelease) => nanos_sdk::exit_app(0),
            io::Event::Command(ins) => match handle_apdu(&mut comm, ins) {
                Ok(()) => comm.reply_ok(),
                Err(sw) => {
                    ui::popup("Erreur2");
                    comm.reply(sw);
                }
            },
            _ => (),
        }
    }
}

#[repr(u8)]
enum Ins {
    GetPubkey,
    RecInt,
    RecField,
    Menu,
    ShowPrivateKey,
    Exit,
}

impl From<u8> for Ins {
    fn from(ins: u8) -> Ins {
        match ins {
            1 => Ins::GetPubkey,
            2 => Ins::Menu,
            3 => Ins::RecInt,
            4 => Ins::RecField,
            0xfe => Ins::ShowPrivateKey,
            0xff => Ins::Exit,
            _ => panic!(),
        }
    }
}

use nanos_sdk::io::Reply;

fn handle_apdu(comm: &mut io::Comm, ins: Ins) -> Result<(), Reply> {
    if comm.rx == 0 {
        ui::popup("Erreur1");
        return Err(io::StatusWords::NothingReceived.into());
    }

    match ins {
        Ins::GetPubkey => comm.append(&get_pubkey()?.W),
        Ins::Menu => menu_example(),
        Ins::ShowPrivateKey => comm.append(&bip32_derive_secp256k1(&BIP32_PATH)?),
        Ins::Exit => nanos_sdk::exit_app(0),
        Ins::RecInt => {
            let mut int1_bytes: [u8; 4] = [0; 4];
            int1_bytes[0] = comm.apdu_buffer[4];
            int1_bytes[1] = comm.apdu_buffer[5];
            int1_bytes[2] = comm.apdu_buffer[6];
            int1_bytes[3] = comm.apdu_buffer[7];
            {
                let hex0 = utils::to_hex(&comm.apdu_buffer[4..8]).unwrap();
                let m = from_utf8(&hex0).unwrap();
                ui::popup(m);
            }
            let mut int2_bytes: [u8; 4] = [0; 4];
            int2_bytes[0] = comm.apdu_buffer[8];
            int2_bytes[1] = comm.apdu_buffer[9];
            int2_bytes[2] = comm.apdu_buffer[10];
            int2_bytes[3] = comm.apdu_buffer[11];
            {
                let hex0 = utils::to_hex(&comm.apdu_buffer[8..12]).unwrap();
                let m = from_utf8(&hex0).unwrap();
                ui::popup(m);
            }
            let sum = u32::from_be_bytes(int1_bytes) + u32::from_be_bytes(int2_bytes);
            comm.append(&sum.to_be_bytes());
        }
        Ins::RecField => {
            // déclaration
            let mut point_sum = 0_u32;
            let mut sum_bytes: [u8; N_BYTES as usize] = [0; N_BYTES as usize];
            let sum_bytes_ptr: *mut u8 = sum_bytes.as_mut_ptr();

            {
                let mut point1 = 0_u32;
                let mut point2 = 0_u32;

                {
                let mut p1_bytes: [u8; N_BYTES as usize] = [0; N_BYTES as usize];
                let ptr_p1_bytes: *const u8 = p1_bytes.as_ptr();

                    for i in 0..N_BYTES {
                        p1_bytes[i as usize] = comm.apdu_buffer[4_usize + i as usize];
                    }
                    unsafe {
                        bindings::cx_bn_lock(N_BYTES, 0);
                        match bindings::cx_bn_alloc_init(
                            &mut point1,
                            N_BYTES,
                            ptr_p1_bytes,
                            N_BYTES,
                        ) {
                            bindings::CX_OK => {
                                ui::popup("Success alloc");
                            }
                            bindings::CX_MEMORY_FULL => ui::popup("Memory full"),
                            bindings::CX_INVALID_PARAMETER_SIZE => ui::popup("Invalid size"),
                            _ => {
                                ui::popup("Erreur inconnue");
                            }
                        }
                        bindings::cx_bn_unlock();
                    }
                }

                {
                    let mut p2_bytes: [u8; N_BYTES as usize] = [0; N_BYTES as usize];
                    let ptr_p2_bytes: *const u8 = p2_bytes.as_ptr();

                    for i in 0..N_BYTES {
                        p2_bytes[i as usize] =
                            comm.apdu_buffer[4_usize + i as usize + N_BYTES as usize];
                    }
                    unsafe {
                        bindings::cx_bn_lock(N_BYTES, 0);
                        match bindings::cx_bn_alloc_init(
                            &mut point2,
                            N_BYTES,
                            ptr_p2_bytes,
                            N_BYTES,
                        ) {
                            bindings::CX_OK => {
                                ui::popup("Success alloc");
                            }
                            bindings::CX_MEMORY_FULL => ui::popup("Memory full"),
                            bindings::CX_INVALID_PARAMETER_SIZE => ui::popup("Invalid size"),
                            _ => {
                                ui::popup("Erreur inconnue");
                            }
                        }
                        bindings::cx_bn_unlock();
                    }
                }

                // on a récupéré la valeur des deux points. On crée maintenant le point qui vaut la somme
                unsafe {
                    bindings::cx_bn_lock(N_BYTES, 0);
                    match bindings::cx_bn_alloc(&mut point_sum, N_BYTES) {
                        bindings::CX_OK => {
                            ui::popup("Success alloc");
                        }
                        bindings::CX_MEMORY_FULL => ui::popup("Memory full"),
                        bindings::CX_INVALID_PARAMETER_SIZE => ui::popup("Invalid size"),
                        _ => {
                            ui::popup("Erreur inconnue");
                        }
                    }
                }
                let copy_p1 = point1;
                let copy_p2 = point2;
                unsafe {
                    bindings::cx_bn_add(point_sum, copy_p1, copy_p2);
                    bindings::cx_bn_unlock();
                }
            }
            unsafe {
                bindings::cx_bn_lock(N_BYTES, 0);

                // debug
                // let test = bindings::cx_bn_export(point_sum, sum_bytes_ptr, N_BYTES);

                // {
                //     let hex0 = utils::to_hex(&u32::to_be_bytes(test as u32)).unwrap();
                //     let m = from_utf8(&hex0).unwrap();
                //     ui::popup(m);
                // }

                match bindings::cx_bn_export(point_sum, sum_bytes_ptr, N_BYTES) {
                    bindings::CX_OK => {
                        ui::popup("Success export");
                    }
                    bindings::CX_INVALID_PARAMETER_VALUE => ui::popup("invalid value"),
                    bindings::CX_INVALID_PARAMETER_SIZE => ui::popup("Invalid size"),
                    bindings::CX_INVALID_PARAMETER => ui::popup("Invalid param"),
                    bindings::CX_MEMORY_FULL => ui::popup("Mem full"),
                    _ => {
                        ui::popup("Erreur inc export");
                    }
                }
                bindings::cx_bn_unlock();
            }
            comm.append(&sum_bytes)
        }
    }
    Ok(())
}
