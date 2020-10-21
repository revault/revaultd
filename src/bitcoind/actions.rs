use crate::{
    bitcoind::{interface::BitcoinD, BitcoindError},
    config::BitcoindConfig,
};

use std::{thread, time};

fn check_bitcoind_network(
    bitcoind: &BitcoinD,
    config_network: &String,
) -> Result<(), BitcoindError> {
    let chaininfo = bitcoind.getblockchaininfo()?;
    let chain = chaininfo
        .get("chain")
        .and_then(|c| c.as_str())
        .ok_or_else(|| {
            BitcoindError("No valid 'chain' in getblockchaininfo response?".to_owned())
        })?;

    if !config_network.eq(chain) {
        return Err(BitcoindError(format!(
            "Wrong network, bitcoind is on '{}' but our config says '{}'",
            chain, config_network
        )));
    }

    Ok(())
}

/// Some sanity checks to be done at startup to make sure our bitcoind isn't going to fail under
/// our feet for a legitimate reason.
pub fn bitcoind_sanity_checks(
    bitcoind: &BitcoinD,
    bitcoind_config: &BitcoindConfig,
) -> Result<(), BitcoindError> {
    check_bitcoind_network(&bitcoind, &bitcoind_config.network)
}

/// Polls bitcoind until we are synced.
/// Tries to be smart with getblockchaininfo calls.
pub fn wait_for_bitcoind_synced(
    bitcoind: &BitcoinD,
    bitcoind_config: &BitcoindConfig,
) -> Result<(), BitcoindError> {
    // We need to take the edge case in which all headers aren't downloaded yet
    // into account.
    let mut first = true;

    loop {
        let chaininfo = bitcoind.getblockchaininfo()?;
        let (headers, blocks, ibd) = (
            chaininfo
                .get("headers")
                .and_then(|h| h.as_u64())
                .ok_or_else(|| {
                    BitcoindError("No valid 'headers' in getblockchaininfo response?".to_owned())
                })?,
            chaininfo
                .get("blocks")
                .and_then(|b| b.as_u64())
                .ok_or_else(|| {
                    BitcoindError("No valid 'blocks' in getblockchaininfo response?".to_owned())
                })?,
            chaininfo
                .get("initialblockdownload")
                .and_then(|i| i.as_bool())
                .ok_or_else(|| {
                    BitcoindError(
                        "No valid 'initialblockdownload' in getblockchaininfo response?".to_owned(),
                    )
                })?,
        );
        let mut delta = if headers > blocks {
            headers - blocks
        } else {
            0
        };

        if ibd {
            // Ok, so we have some time. Let's try to avoid slowing it down by
            // spamming it with getblockchaininfo calls.

            // FIXME: log here

            // First: wait for it to gather all headers, if the current delta is
            // big enough. let's assume it won't take longer than 5min from now
            // for mainnet.
            // Then: get the number of blocks left to DL
            if first || delta > 1_000 {
                if bitcoind_config.network.eq("regtest") {
                    thread::sleep(time::Duration::from_secs(3));
                } else {
                    thread::sleep(time::Duration::from_secs(5 * 60));
                }

                let chaininfo = bitcoind.getblockchaininfo()?;
                let (headers, blocks) = (
                    chaininfo
                        .get("headers")
                        .and_then(|h| h.as_u64())
                        .ok_or_else(|| {
                            BitcoindError(
                                "No valid 'headers' in getblockchaininfo response?".to_owned(),
                            )
                        })?,
                    chaininfo
                        .get("blocks")
                        .and_then(|b| b.as_u64())
                        .ok_or_else(|| {
                            BitcoindError(
                                "No valid 'blocks' in getblockchaininfo response?".to_owned(),
                            )
                        })?,
                );
                delta = headers - blocks;
            }
        } else if delta == 0 {
            return Ok(());
        }

        // FIXME: log here

        // Sleeping a second per 20 blocks seems a good upper bound estimation
        // (~7h for 500_000 blocks), so we divide it by 2 here in order to be
        // conservative. Eg if 10_000 are left to be downloaded we'll check back
        // in ~4min.
        // FIXME: maybe Edouard will need more fine-grained updates eventually
        thread::sleep(time::Duration::from_secs(delta / 20 / 2));

        first = false;
    }
}
