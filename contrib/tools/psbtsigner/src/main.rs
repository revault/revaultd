use std::{env, process, str::FromStr};

use revault_tx::{
    bitcoin::{
        consensus::encode::{deserialize, serialize},
        secp256k1,
        util::{bip143::SigHashCache, psbt::PartiallySignedTransaction as Psbt},
        PrivateKey, SigHash, SigHashType,
    },
    miniscript::descriptor::DescriptorSecretKey,
};

fn parse_args(args: Vec<String>) -> (PrivateKey, Psbt, usize) {
    if args.len() < 3 {
        eprintln!(
            "Usage: '{} <xpriv/derivation/path OR wif_privkey> <psbt> [input index]'",
            args[0]
        );
        process::exit(1);
    }

    let key = DescriptorSecretKey::from_str(&args[1]).unwrap_or_else(|e| {
        eprintln!("Error parsing private key: '{}'", e);
        process::exit(1);
    });
    let key = match key {
        DescriptorSecretKey::SinglePriv(single_priv) => single_priv.key,
        DescriptorSecretKey::XPrv(xpriv) => {
            let secp = secp256k1::Secp256k1::signing_only();
            xpriv
                .xkey
                .derive_priv(&secp, &xpriv.derivation_path)
                .unwrap()
                .private_key
        }
    };
    let psbt = base64::decode(&args[2]).unwrap_or_else(|e| {
        eprintln!("PSBT is invalid base64: '{}'", e);
        process::exit(1);
    });
    let psbt: Psbt = deserialize(&psbt).unwrap_or_else(|e| {
        eprintln!("Error parsing PSBT: '{}'", e);
        process::exit(1);
    });
    let input_index = args
        .get(3)
        .map(|i| {
            i.parse::<usize>().unwrap_or_else(|e| {
                eprintln!("Parsing input index: '{}'", e);
                process::exit(1);
            })
        })
        .unwrap_or_else(|| {
            println!("  ---> No input index specified. Using `0`.");
            0
        });

    (key, psbt, input_index)
}

fn sighash(psbt: &Psbt, input_index: usize) -> (SigHash, SigHashType) {
    let mut cache = SigHashCache::new(&psbt.global.unsigned_tx);
    let psbtin = psbt.inputs.get(input_index).unwrap_or_else(|| {
        eprintln!("Psbt has no input at index '{}'", input_index);
        process::exit(1);
    });
    let prev_value = psbtin
        .witness_utxo
        .as_ref()
        .unwrap_or_else(|| {
            eprintln!("Psbt has no witness utxo for input '{:?}'", psbtin);
            process::exit(1);
        })
        .value;
    let script_code = psbtin.witness_script.as_ref().unwrap_or_else(|| {
        eprintln!("Psbt input has no witness Script. We only support signing for P2WSH.");
        process::exit(1);
    });
    let sighash_type = psbtin.sighash_type.unwrap_or_else(|| {
        println!("  ---> Psbt input has no sighash type specified. Using SIGHASH_ALL.");
        SigHashType::All
    });

    (
        cache.signature_hash(input_index, &script_code, prev_value, sighash_type),
        sighash_type,
    )
}

fn sign_psbt(key: PrivateKey, psbt: &mut Psbt, input_index: usize) {
    let secp = secp256k1::Secp256k1::signing_only();
    let (sighash, sighash_type) = sighash(&psbt, input_index);
    let sighash = secp256k1::Message::from_slice(&sighash).expect("Sighash is 32 bytes");

    let mut signature = secp.sign(&sighash, &key.key).serialize_der().to_vec();
    signature.push(sighash_type.as_u32() as u8);
    let pubkey = key.public_key(&secp);
    psbt.inputs[0].partial_sigs.insert(pubkey, signature);
}

fn main() {
    let (privkey, mut psbt, index) = parse_args(env::args().collect());
    sign_psbt(privkey, &mut psbt, index);

    let raw_psbt = serialize(&psbt);
    println!("Signed PSBT:\n{}", base64::encode(raw_psbt));
}
