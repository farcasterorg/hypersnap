use hypersnap_crypto::bulletproofs::curve_adapter::Scalar;
use hypersnap_crypto::tokens::point_from_compressed_bytes;
use hypersnap_crypto::tokens::{scan_stealth_note, StealthKeypair};

pub struct OwnedNote {
    pub commitment_bytes: Vec<u8>,
    pub spend_secret: Scalar,
    pub tx_pubkey_bytes: Vec<u8>,
    pub one_time_pubkey_bytes: Vec<u8>,
}

pub struct ChainOutput {
    pub tx_pubkey: Vec<u8>,
    pub one_time_pubkey: Vec<u8>,
    pub commitment: Vec<u8>,
}

pub fn scan_notes(keypair: &StealthKeypair, outputs: &[ChainOutput]) -> Vec<OwnedNote> {
    outputs
        .iter()
        .filter_map(|out| {
            if out.tx_pubkey.len() != 56 || out.one_time_pubkey.len() != 56 {
                return None;
            }
            let mut tx_bytes = [0u8; 56];
            tx_bytes.copy_from_slice(&out.tx_pubkey);
            let mut otp_bytes = [0u8; 56];
            otp_bytes.copy_from_slice(&out.one_time_pubkey);
            let tx_pk = point_from_compressed_bytes(&tx_bytes)?;
            let otp = point_from_compressed_bytes(&otp_bytes)?;
            let spend_secret = scan_stealth_note(keypair, &tx_pk, &otp)?;
            Some(OwnedNote {
                commitment_bytes: out.commitment.clone(),
                spend_secret,
                tx_pubkey_bytes: out.tx_pubkey.clone(),
                one_time_pubkey_bytes: out.one_time_pubkey.clone(),
            })
        })
        .collect()
}
