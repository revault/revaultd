use std::{env, process, str::FromStr};

use revault_tx::{
    bitcoin::util::bip32,
    miniscript::descriptor::{DescriptorPublicKey, DescriptorXKey, Wildcard},
    scripts::{CpfpDescriptor, DepositDescriptor, UnvaultDescriptor},
};

macro_rules! from_json {
    ($str:expr) => {
        serde_json::from_str($str).unwrap_or_else(|e| {
            eprintln!("Failed to deserialize '{}' as JSON: '{}'", $str, e);
            process::exit(1);
        });
    };
}

fn xpubs_from_json(json_array: &str) -> Vec<DescriptorPublicKey> {
    let keys: Vec<String> = from_json!(json_array);
    keys.into_iter()
        .map(|key_str| {
            let xpub = bip32::ExtendedPubKey::from_str(&key_str).unwrap_or_else(|e| {
                eprintln!("Failed to parse xpub '{}': '{}'", &key_str, e);
                process::exit(1);
            });
            DescriptorPublicKey::XPub(DescriptorXKey {
                origin: None,
                xkey: xpub,
                derivation_path: vec![].into(),
                wildcard: Wildcard::Unhardened
            })
        })
        .collect()
}

fn keys_from_json(json_array: &str) -> Vec<DescriptorPublicKey> {
    let keys: Vec<String> = from_json!(json_array);
    keys.into_iter()
        .map(|key_str| {
            DescriptorPublicKey::from_str(&key_str).unwrap_or_else(|e| {
                eprintln!("Failed to parse xpub '{}': '{}'", &key_str, e);
                process::exit(1);
            })
        })
        .collect()
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 7 {
        eprintln!(
            "Usage: '{} <stakeholders xpubs> <cosigs pubkeys> <managers xpubs> \
             <managers threshold> <cpfp xpubs> <Unvault CSV>'\n \
             All values are as JSON.",
            args[0]
        );
        process::exit(1);
    }

    let stk_keys = xpubs_from_json(&args[1]);
    let cosigs_keys = keys_from_json(&args[2]);
    let man_keys = xpubs_from_json(&args[3]);
    let man_thresh: u32 = from_json!(&args[4]);
    let cpfp_xpubs = xpubs_from_json(&args[5]);
    let unvault_csv: u32 = from_json!(&args[6]);

    let deposit_desc = DepositDescriptor::new(stk_keys.clone()).unwrap_or_else(|e| {
        eprintln!("Compiling Deposit descriptor: '{}'", e);
        process::exit(1);
    });
    let unvault_desc = UnvaultDescriptor::new(
        stk_keys,
        man_keys,
        man_thresh as usize,
        cosigs_keys,
        unvault_csv,
    )
    .unwrap_or_else(|e| {
        eprintln!("Compiling Unvault descriptor: '{}'", e);
        process::exit(1);
    });
    let cpfp_desc = CpfpDescriptor::new(cpfp_xpubs).unwrap_or_else(|e| {
        eprintln!("Compiling CPFP descriptor: '{}'", e);
        process::exit(1);
    });

    let dep_str: serde_json::Value = deposit_desc.to_string().into();
    let unv_str: serde_json::Value = unvault_desc.to_string().into();
    let cpfp_str: serde_json::Value = cpfp_desc.to_string().into();
    println!(
        "{:#}",
        serde_json::json!({
            "deposit_descriptor": dep_str,
            "unvault_descriptor": unv_str,
            "cpfp_descriptor": cpfp_str,
        })
    );
}
