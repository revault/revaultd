/// This is where we regroup all logic related to the storage and management of
/// in-DB pre-signed *Bitcoin* transactions (not to be confused with DB txs).
use revault_tx::{
    bitcoin::{secp256k1, Txid, Wtxid},
    transactions::{
        CancelTransaction, EmergencyTransaction, RevaultTransaction, UnvaultEmergencyTransaction,
        UnvaultTransaction,
    },
};

use std::{collections, convert::TryFrom};

/// The type of the transaction, as stored in the "presigned_transactions" table
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TransactionType {
    Unvault,
    Cancel,
    Emergency,
    UnvaultEmergency,
}

impl TryFrom<u32> for TransactionType {
    type Error = ();

    fn try_from(n: u32) -> Result<Self, Self::Error> {
        match n {
            0 => Ok(Self::Unvault),
            1 => Ok(Self::Cancel),
            2 => Ok(Self::Emergency),
            3 => Ok(Self::UnvaultEmergency),
            _ => Err(()),
        }
    }
}

macro_rules! tx_type_from_tx {
    ($tx:ident, $tx_type:ident) => {
        impl From<&$tx> for TransactionType {
            fn from(_: &$tx) -> Self {
                Self::$tx_type
            }
        }
    };
}
tx_type_from_tx!(UnvaultTransaction, Unvault);
tx_type_from_tx!(CancelTransaction, Cancel);
tx_type_from_tx!(EmergencyTransaction, Emergency);
tx_type_from_tx!(UnvaultEmergencyTransaction, UnvaultEmergency);

// FIXME: move it into its own file
/// A transaction stored in the 'presigned_transactions' table
#[derive(Debug, PartialEq, Clone)]
pub enum RevaultTx {
    Unvault(UnvaultTransaction),
    Cancel(CancelTransaction),
    Emergency(EmergencyTransaction),
    UnvaultEmergency(UnvaultEmergencyTransaction),
}

impl RevaultTx {
    /// Serialize in the PSBT format
    pub fn ser(&self) -> Vec<u8> {
        match self {
            RevaultTx::Unvault(ref tx) => tx.as_psbt_serialized(),
            RevaultTx::Cancel(ref tx) => tx.as_psbt_serialized(),
            RevaultTx::Emergency(ref tx) => tx.as_psbt_serialized(),
            RevaultTx::UnvaultEmergency(ref tx) => tx.as_psbt_serialized(),
        }
    }

    /// Add a signature to a presigned transaction (always first index)
    pub fn add_signature<C>(
        &mut self,
        secp: &secp256k1::Secp256k1<C>,
        pubkey: secp256k1::PublicKey,
        sig: secp256k1::Signature,
    ) -> Result<Option<Vec<u8>>, revault_tx::error::InputSatisfactionError>
    where
        C: secp256k1::Verification,
    {
        match self {
            RevaultTx::Unvault(ref mut tx) => tx.add_sig(pubkey, sig, secp),
            RevaultTx::Cancel(ref mut tx) => tx.add_cancel_sig(pubkey, sig, secp),
            RevaultTx::Emergency(ref mut tx) => tx.add_emer_sig(pubkey, sig, secp),
            RevaultTx::UnvaultEmergency(ref mut tx) => tx.add_emer_sig(pubkey, sig, secp),
        }
    }

    /// Get the txid of the inner tx of the PSBT
    pub fn txid(&self) -> Txid {
        match self {
            RevaultTx::Unvault(ref tx) => tx.txid(),
            RevaultTx::Cancel(ref tx) => tx.txid(),
            RevaultTx::Emergency(ref tx) => tx.txid(),
            RevaultTx::UnvaultEmergency(ref tx) => tx.txid(),
        }
    }

    /// Get the wtxid of the inner tx of the PSBT
    pub fn wtxid(&self) -> Wtxid {
        match self {
            RevaultTx::Unvault(ref tx) => tx.wtxid(),
            RevaultTx::Cancel(ref tx) => tx.wtxid(),
            RevaultTx::Emergency(ref tx) => tx.wtxid(),
            RevaultTx::UnvaultEmergency(ref tx) => tx.wtxid(),
        }
    }

    /// Get the signatures of this presigned transaction.
    /// All presigned transactions only have a single input (at least before fee-bumping,
    /// but such transactions are never stored in our DB).
    ///
    /// # Panics
    /// - If the PSBT doesn't contain at least one PSBT input
    /// - If the PSBT contains an invalid signature
    pub fn signatures(&self) -> collections::BTreeMap<secp256k1::PublicKey, secp256k1::Signature> {
        let sigs = match self {
            RevaultTx::Unvault(ref tx) => &tx.psbt().inputs[0].partial_sigs,
            RevaultTx::Cancel(ref tx) => &tx.psbt().inputs[0].partial_sigs,
            RevaultTx::Emergency(ref tx) => &tx.psbt().inputs[0].partial_sigs,
            RevaultTx::UnvaultEmergency(ref tx) => &tx.psbt().inputs[0].partial_sigs,
        };

        sigs.iter()
            .map(|(pk, sig)| {
                assert!(!sig.is_empty());
                let sig = secp256k1::Signature::from_der(&sig[..sig.len() - 1])
                    .expect("DB transaction are assumed to only contain valid sigs");
                (pk.key, sig)
            })
            .collect()
    }

    pub fn unwrap_unvault(&self) -> &UnvaultTransaction {
        match self {
            RevaultTx::Unvault(ref tx) => tx,
            _ => unreachable!("It must be an unvault!"),
        }
    }

    pub fn unwrap_cancel(&self) -> &CancelTransaction {
        match self {
            RevaultTx::Cancel(ref tx) => tx,
            _ => unreachable!("it must be a cancel!"),
        }
    }

    pub fn unwrap_emer(&self) -> &EmergencyTransaction {
        match self {
            RevaultTx::Emergency(ref tx) => tx,
            _ => unreachable!("It must be an emer!"),
        }
    }

    pub fn unwrap_unvault_emer(&self) -> &UnvaultEmergencyTransaction {
        match self {
            RevaultTx::UnvaultEmergency(ref tx) => tx,
            _ => unreachable!("It must be an unvaultemer!"),
        }
    }

    pub fn assert_unvault(self) -> UnvaultTransaction {
        match self {
            RevaultTx::Unvault(tx) => tx,
            _ => unreachable!("It must be an unvault!"),
        }
    }

    pub fn assert_cancel(self) -> CancelTransaction {
        match self {
            RevaultTx::Cancel(tx) => tx,
            _ => unreachable!("it must be a cancel!"),
        }
    }

    pub fn assert_emer(self) -> EmergencyTransaction {
        match self {
            RevaultTx::Emergency(tx) => tx,
            _ => unreachable!("It must be an emer!"),
        }
    }

    pub fn assert_unvault_emer(self) -> UnvaultEmergencyTransaction {
        match self {
            RevaultTx::UnvaultEmergency(tx) => tx,
            _ => unreachable!("It must be an unvaultemer!"),
        }
    }
}
