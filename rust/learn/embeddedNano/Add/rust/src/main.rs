#![no_std]
#![no_main]

mod crypto_helpers;
mod utils;

use core::str::from_utf8;
use crypto_helpers::*;
use nanos_sdk::bindings;
use nanos_sdk::buttons::ButtonEvent;
use nanos_sdk::io;
use nanos_sdk::io::SyscallError;
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

fn add_int(message: &[u8]) -> Result<[u8; 4], SyscallError> {
    ui::popup("Add int ?"); // à modif avec ask

    let mut int1_bytes: [u8; 4] = [0; 4];
    int1_bytes[0] = message[0];
    int1_bytes[1] = message[1];
    int1_bytes[2] = message[2];
    int1_bytes[3] = message[3];

    {
        let hex = utils::to_hex(&message[0..4]).map_err(|_| SyscallError::Overflow)?;
        let m = from_utf8(&hex).map_err(|_| SyscallError::InvalidParameter)?;
        ui::popup("Int 1");
        ui::popup(m);
    }

    let mut int2_bytes: [u8; 4] = [0; 4];
    int2_bytes[0] = message[4];
    int2_bytes[1] = message[5];
    int2_bytes[2] = message[6];
    int2_bytes[3] = message[7];

    {
        let hex = utils::to_hex(&message[4..8]).map_err(|_| SyscallError::Overflow)?;
        let m = from_utf8(&hex).map_err(|_| SyscallError::InvalidParameter)?;
        ui::popup("Int 2");
        ui::popup(m);
    }

    Ok((u32::from_be_bytes(int1_bytes) + u32::from_be_bytes(int2_bytes)).to_be_bytes())
}

fn add_field(message: &[u8]) -> Result<[u8; N_BYTES as usize], SyscallError> {
    // on essaye d'optimiser la place sur la stack avec les {}
    ui::popup("Add field ?"); // à modif avec ask

    unsafe {
        match bindings::cx_bn_lock(N_BYTES, 0) {
            bindings::CX_OK => (),
            bindings::CX_LOCKED => return Err(SyscallError::InvalidState),
            _ => return Err(SyscallError::Unspecified),
        }
    }
    // déclaration
    let mut point_sum = 0_u32;
    let mut sum_bytes: [u8; N_BYTES as usize] = [0; N_BYTES as usize];
    let sum_bytes_ptr: *mut u8 = sum_bytes.as_mut_ptr();

    {
        let mut point1 = 0_u32;
        let mut point2 = 0_u32;

        let mut modulo = 0_u32;

        // allocation et initialisation du field 1
        {
            let mut p1_bytes: [u8; N_BYTES as usize] = [0; N_BYTES as usize];
            let ptr_p1_bytes: *const u8 = p1_bytes.as_ptr();

            for i in 0..N_BYTES {
                p1_bytes[i as usize] = message[i as usize];
            }

            //affichage du Field 1
            {   
                ui::popup("Field1");
                let hex = utils::to_hex(&p1_bytes).map_err(|_| SyscallError::Overflow)?;
                let m = from_utf8(&hex).map_err(|_| SyscallError::InvalidParameter)?;
                ui::MessageScroller::new(m).event_loop();
            }
            unsafe {
                match bindings::cx_bn_alloc_init(&mut point1, N_BYTES, ptr_p1_bytes, N_BYTES) {
                    bindings::CX_OK => (),
                    bindings::CX_MEMORY_FULL => return Err(SyscallError::Overflow),
                    bindings::CX_INVALID_PARAMETER_SIZE => {
                        return Err(SyscallError::InvalidParameter)
                    }
                    _ => return Err(SyscallError::Unspecified),
                }
            }
        }
        // allocation et initialisation du field 2
        {
            let mut p2_bytes: [u8; N_BYTES as usize] = [0; N_BYTES as usize];
            let ptr_p2_bytes: *const u8 = p2_bytes.as_ptr();

            for i in 0..N_BYTES {
                p2_bytes[i as usize] = message[i as usize + N_BYTES as usize];
            }

            //affichage du Field 2
            {   
                ui::popup("Field2");
                let hex = utils::to_hex(&p2_bytes).map_err(|_| SyscallError::Overflow)?;
                let m = from_utf8(&hex).map_err(|_| SyscallError::InvalidParameter)?;
                ui::MessageScroller::new(m).event_loop();
            }
            unsafe {
                match bindings::cx_bn_alloc_init(&mut point2, N_BYTES, ptr_p2_bytes, N_BYTES) {
                    bindings::CX_OK => (),
                    bindings::CX_MEMORY_FULL => return Err(SyscallError::Overflow),
                    bindings::CX_INVALID_PARAMETER_SIZE => return Err(SyscallError::InvalidParameter),
                    _ => return Err(SyscallError::Unspecified),
                }
            }
        }

        // allocation et initialisation de la valeur du modulo (order de secp256k1)
        {
            let mut mod_bytes: [u8; N_BYTES as usize] = [0; N_BYTES as usize]; // mod = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
            for i in 0..(N_BYTES - 17) {
                mod_bytes[i as usize] = 255; // = FF
            }
            mod_bytes[N_BYTES as usize - 17] = 254; // = FE
            mod_bytes[N_BYTES as usize - 16] = 186; // = BA
            mod_bytes[N_BYTES as usize - 15] = 174; // = AE
            mod_bytes[N_BYTES as usize - 14] = 220; // = DC
            mod_bytes[N_BYTES as usize - 13] = 230; // = E6
            mod_bytes[N_BYTES as usize - 12] = 175; // = AF
            mod_bytes[N_BYTES as usize - 11] = 72; // = 48
            mod_bytes[N_BYTES as usize - 10] = 160; // = A0
            mod_bytes[N_BYTES as usize - 9] = 59; // = 3B
            mod_bytes[N_BYTES as usize - 8] = 191; // = BF
            mod_bytes[N_BYTES as usize - 7] = 210; // = D2
            mod_bytes[N_BYTES as usize - 6] = 94; // = 5E
            mod_bytes[N_BYTES as usize - 5] = 140; // = 8C
            mod_bytes[N_BYTES as usize - 4] = 208; // = D0
            mod_bytes[N_BYTES as usize - 3] = 54; // = 36
            mod_bytes[N_BYTES as usize - 2] = 65; // = 41
            mod_bytes[N_BYTES as usize - 1] = 65; // = 41
            let mod_bytes_ptr: *mut u8 = mod_bytes.as_mut_ptr();

            unsafe {
                match bindings::cx_bn_alloc_init(&mut modulo, N_BYTES, mod_bytes_ptr, N_BYTES) {
                    bindings::CX_OK => (),
                    bindings::CX_MEMORY_FULL => return Err(SyscallError::Overflow),
                    bindings::CX_INVALID_PARAMETER_SIZE => return Err(SyscallError::InvalidParameter),
                    _ => return Err(SyscallError::Unspecified),
                }
            }
        }

        // on a récupéré la valeur des deux points. On crée maintenant le point qui vaut la somme
        unsafe {
            match bindings::cx_bn_alloc(&mut point_sum, N_BYTES) {
                bindings::CX_OK => (),
                bindings::CX_MEMORY_FULL => return Err(SyscallError::Overflow),
                bindings::CX_INVALID_PARAMETER_SIZE => return Err(SyscallError::InvalidParameter),
                _ => return Err(SyscallError::Unspecified),
            }
        }
        let copy_p1 = point1;
        let copy_p2 = point2;

        let copy_mod = modulo;

        unsafe { match bindings::cx_bn_mod_add(point_sum, copy_p1, copy_p2, copy_mod) {
            bindings::CX_OK => (),
            bindings::CX_NOT_LOCKED => return Err(SyscallError::InvalidState),
            bindings::CX_INVALID_PARAMETER => return Err(SyscallError::InvalidParameter),
            _ => return Err(SyscallError::Unspecified),
        }
        }
    }

    unsafe {
        match bindings::cx_bn_export(point_sum, sum_bytes_ptr, N_BYTES) {
            bindings::CX_OK => (),
            bindings::CX_INVALID_PARAMETER_VALUE => return Err(SyscallError::InvalidParameter),
            bindings::CX_INVALID_PARAMETER_SIZE => return Err(SyscallError::InvalidParameter),
            bindings::CX_INVALID_PARAMETER => return Err(SyscallError::InvalidParameter),
            bindings::CX_MEMORY_FULL => return Err(SyscallError::Overflow),
            _ => return Err(SyscallError::Unspecified),
        }

        match bindings::cx_bn_unlock() {
            bindings::CX_OK => (),
            bindings::CX_NOT_LOCKED => return Err(SyscallError::InvalidState),
            _ => return Err(SyscallError::Unspecified),
        }
    }
    Ok(sum_bytes)
}

fn add_point(message: &[u8]) -> Result<[u8; 2 * N_BYTES as usize + 1 as usize], SyscallError> {
    ui::popup("Add point ?"); // à modif avec ask

    unsafe {
        match bindings::cx_bn_lock(N_BYTES, 0) {
            bindings::CX_OK => (),
            bindings::CX_LOCKED => return Err(SyscallError::InvalidState),
            _ => return Err(SyscallError::Unspecified),
        }
    }

    let mut sum_bytes: [u8; 2 * N_BYTES as usize + 1] = [0; 2 * N_BYTES as usize + 1]; // ce qu'on cherche à export

    unsafe {
        let mut point1 = bindings::cx_ecpoint_t::default();
        match bindings::cx_ecpoint_alloc(&mut point1, bindings::CX_CURVE_SECP256K1) {
            bindings::CX_OK => (),
            bindings::CX_EC_INVALID_CURVE => return Err(SyscallError::InvalidParameter),
            bindings::CX_NOT_LOCKED => return Err(SyscallError::InvalidState),
            bindings::CX_INVALID_PARAMETER => return Err(SyscallError::InvalidParameter),
            bindings::CX_MEMORY_FULL => return Err(SyscallError::Overflow),
            _ => return Err(SyscallError::Unspecified),
        }

        let mut point2 = bindings::cx_ecpoint_t::default();
        match bindings::cx_ecpoint_alloc(&mut point2, bindings::CX_CURVE_SECP256K1) {
            bindings::CX_OK => (),
            bindings::CX_EC_INVALID_CURVE => return Err(SyscallError::InvalidParameter),
            bindings::CX_NOT_LOCKED => return Err(SyscallError::InvalidState),
            bindings::CX_INVALID_PARAMETER => return Err(SyscallError::InvalidParameter),
            bindings::CX_MEMORY_FULL => return Err(SyscallError::Overflow),
            _ => return Err(SyscallError::Unspecified),
        }

        let mut point_sum = bindings::cx_ecpoint_t::default();
        match bindings::cx_ecpoint_alloc(&mut point_sum, bindings::CX_CURVE_SECP256K1) {
            bindings::CX_OK => (),
            bindings::CX_EC_INVALID_CURVE => return Err(SyscallError::InvalidParameter),
            bindings::CX_NOT_LOCKED => return Err(SyscallError::InvalidState),
            bindings::CX_INVALID_PARAMETER => return Err(SyscallError::InvalidParameter),
            bindings::CX_MEMORY_FULL => return Err(SyscallError::Overflow),
            _ => return Err(SyscallError::Unspecified),
        }

        let mut x_point1_bytes: [u8; N_BYTES as usize] = [0; N_BYTES as usize];
        for i in 0..N_BYTES {
            x_point1_bytes[i as usize] = message[1 + i as usize];
        }

        let mut y_point1_bytes: [u8; N_BYTES as usize] = [0; N_BYTES as usize];
        for i in 0..N_BYTES {
            y_point1_bytes[i as usize] =
            message[1 + N_BYTES as usize + i as usize];
        }

        let point1_ptr: *mut bindings::cx_ecpoint_t = &mut point1;
        bindings::cx_ecpoint_init(
            point1_ptr,
            x_point1_bytes.as_ptr(),
            N_BYTES,
            y_point1_bytes.as_ptr(),
            N_BYTES,
        );

        let mut x_point2_bytes: [u8; N_BYTES as usize] = [0; N_BYTES as usize];
        for i in 0..N_BYTES {
            x_point2_bytes[i as usize] =
            message[2 + i as usize + 2 * N_BYTES as usize];
        }

        let mut y_point2_bytes: [u8; N_BYTES as usize] = [0; N_BYTES as usize];
        for i in 0..N_BYTES {
            y_point2_bytes[i as usize] =
            message[2 + 3 * N_BYTES as usize + i as usize];
        }

        let point2_ptr: *mut bindings::cx_ecpoint_t = &mut point2;
        bindings::cx_ecpoint_init(
            point2_ptr,
            x_point2_bytes.as_ptr(),
            N_BYTES,
            y_point2_bytes.as_ptr(),
            N_BYTES,
        );

        let point_sum_ptr: *mut bindings::cx_ecpoint_t = &mut point_sum;
        let point1_ptr_copy = point1_ptr;
        let point2_ptr_copy = point2_ptr;

        // on fait l'addition des deux points

        match bindings::cx_ecpoint_add(point_sum_ptr, point1_ptr_copy, point2_ptr_copy) {
            bindings::CX_OK => (),
            bindings::CX_EC_INVALID_CURVE => return Err(SyscallError::InvalidParameter),
            bindings::CX_NOT_LOCKED => return Err(SyscallError::InvalidState),
            bindings::CX_INVALID_PARAMETER => return Err(SyscallError::InvalidParameter),
            bindings::CX_EC_INVALID_POINT => return Err(SyscallError::InvalidParameter),
            bindings::CX_EC_INFINITE_POINT => return Err(SyscallError::InvalidParameter),
            bindings::CX_MEMORY_FULL => return Err(SyscallError::Overflow),
            _ => return Err(SyscallError::Unspecified),
        }

        //on export on renvoie en non compressé :

        let mut x_sum_bytes: [u8; N_BYTES as usize] = [0; N_BYTES as usize];
        let mut y_sum_bytes: [u8; N_BYTES as usize] = [0; N_BYTES as usize];

        match bindings::cx_ecpoint_export(
            point_sum_ptr,
            x_sum_bytes.as_mut_ptr(),
            N_BYTES,
            y_sum_bytes.as_mut_ptr(),
            N_BYTES,
        ) {
            bindings::CX_OK => (),
            bindings::CX_INVALID_PARAMETER_VALUE => return Err(SyscallError::InvalidParameter),
            bindings::CX_INVALID_PARAMETER_SIZE => return Err(SyscallError::InvalidParameter),
            bindings::CX_INVALID_PARAMETER => return Err(SyscallError::InvalidParameter),
            bindings::CX_MEMORY_FULL => return Err(SyscallError::Overflow),
            _ => return Err(SyscallError::Unspecified),
        }

        sum_bytes[0] = 4; // on dit qu'on fait non compressé;
        for i in 0..N_BYTES {
            sum_bytes[1 + i as usize] = x_sum_bytes[i as usize];
            sum_bytes[1 + i as usize + N_BYTES as usize] = y_sum_bytes[i as usize];
        }
    }
    unsafe {
        match bindings::cx_bn_unlock() {
            bindings::CX_OK => (),
            bindings::CX_NOT_LOCKED => return Err(SyscallError::InvalidState),
            _ => return Err(SyscallError::Unspecified),
        }
    }
    Ok(sum_bytes)
}

#[repr(u8)]
enum Ins {
    GetPubkey,
    RecInt,
    RecField,
    RecPoint,
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
            5 => Ins::RecPoint,
            0xfe => Ins::ShowPrivateKey,
            0xff => Ins::Exit,
            _ => panic!(),
        }
    }
}

use nanos_sdk::io::Reply;

fn handle_apdu(comm: &mut io::Comm, ins: Ins) -> Result<(), Reply> {
    if comm.rx == 0 {
        return Err(io::StatusWords::NothingReceived.into());
    }

    match ins {
        Ins::GetPubkey => comm.append(&get_pubkey()?.W),
        Ins::Menu => menu_example(),
        Ins::ShowPrivateKey => comm.append(&bip32_derive_secp256k1(&BIP32_PATH)?),
        Ins::Exit => nanos_sdk::exit_app(0),
        Ins::RecInt => {
            let out = add_int(comm.get_data()?);
            match out {
                Ok(o) => comm.append(&o),
                Err(e) => comm.reply(e),
            }
        }
        Ins::RecField => {
            let out = add_field(comm.get_data()?);
            match out {
                Ok(o) => comm.append(&o),
                Err(e) => comm.reply(e),
            }
        }
        Ins::RecPoint => {
            let out = add_point(comm.get_data()?);
            match out {
                Ok(o) => comm.append(&o),
                Err(e) => comm.reply(e),
            }
        }
    }
    Ok(())
}
