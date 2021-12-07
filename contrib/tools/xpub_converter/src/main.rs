use bitcoin::{
    network::constants::Network,
    util::{
        base58,
        bip32::{ExtendedPrivKey, ExtendedPubKey},
    },
};
use std::{collections::VecDeque, env};

fn main() -> Result<(), String> {
    let args: VecDeque<String> = env::args().collect();
    let (network, mut xpub, mut xpriv) = parse_arguments(args.clone()).map_err(|e| {
        print_usage(&args[0]);
        e
    })?;

    if let Some(xpub) = &mut xpub {
        xpub.network = network;
        println!("xpub: {}", xpub);
    }

    if let Some(xpriv) = &mut xpriv {
        xpriv.network = network;
        println!("xpriv: {}", xpriv);
    }

    Ok(())
}

fn parse_arguments(
    mut args: VecDeque<String>,
) -> Result<(Network, Option<ExtendedPubKey>, Option<ExtendedPrivKey>), String> {
    let mut network: Option<Network> = None;
    let mut xpub: Option<ExtendedPubKey> = None;
    let mut xpriv: Option<ExtendedPrivKey> = None;

    // Popping the first argument (command name)
    args.pop_front();

    while args.len() >= 2 {
        let arg = args.pop_front().expect("We check args len in the loop");
        if &arg == "--network" {
            network = match args.pop_front().expect("We check args len in the loop").as_str() {
                "mainnet" | "bitcoin" => Some(Network::Bitcoin),
                "testnet" => Some(Network::Testnet),
                "regtest" => Some(Network::Regtest),
                "signet" => Some(Network::Signet),
                _ => return Err("Invalid network provided. Choose one between 'mainnet', 'testnet', 'regtest', 'signet'".to_string()),
            };
        } else if &arg == "--xpub" {
            let key = args.pop_front().expect("We check args len in the loop");
            xpub = Some(
                base58::from(&key)
                    .map_err(|e| format!("Invalid xpub: {}", e))
                    .and_then(|k| {
                        ExtendedPubKey::decode(&k[0..78])
                            .map_err(|e| format!("Invalid xpub: {}", e))
                    })?,
            );
        } else if &arg == "--xpriv" {
            let key = args.pop_front().expect("We check args len in the loop");
            xpriv = Some(
                base58::from(&key)
                    .map_err(|e| format!("Invalid xpriv: {}", e))
                    .and_then(|k| {
                        ExtendedPrivKey::decode(&k[0..78])
                            .map_err(|e| format!("Invalid xpriv: {}", e))
                    })?,
            );
        }
    }

    let network = match network {
        Some(n) => n,
        None => {
            return Err("Missing network".to_string());
        }
    };

    if xpub.is_none() && xpriv.is_none() {
        return Err("Provide at least one between xpub, xpriv".to_string());
    }

    Ok((network, xpub, xpriv))
}

fn print_usage(command_name: &str) {
    eprintln!(
        "Usage: '{} --network <network> [--xpub <xpub>] [--xpriv <xpriv>] \
             At least one between xpub and xpriv must be present.\n",
        command_name,
    );
}
