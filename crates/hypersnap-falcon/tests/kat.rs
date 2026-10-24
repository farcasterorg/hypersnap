//! Known-answer tests.
//!
//! Each vector fixes a key-generation seed, a ChaCha20 seed for the signing
//! RNG, a domain and a payload. The expected values were made once with this
//! crate on fn-dsa 0.4.0 and are hard-coded here. They pin:
//!
//! - the key pair of each seed (`keccak256` of the public and secret keys);
//! - the full signature, which must verify;
//! - deterministic signing for a fixed RNG output (fn-dsa hedged signing).
//!
//! If a dependency change breaks one of these, it is a consensus change.

use hypersnap_falcon::{
    domains, keccak256, keygen_from_seed, sign, verify, verify_bytes, Domain, FalconError,
    FalconSignature,
};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

const SEED_RAMP: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

enum Payload {
    Empty,
    Text(&'static [u8]),
    /// 1000 bytes: byte i is `i % 251`.
    Ramp1000,
}

impl Payload {
    fn bytes(&self) -> Vec<u8> {
        match self {
            Payload::Empty => Vec::new(),
            Payload::Text(t) => t.to_vec(),
            Payload::Ramp1000 => (0..1000u32).map(|i| (i % 251) as u8).collect(),
        }
    }
}

struct Kat {
    seed: [u8; 32],
    sign_rng_seed: [u8; 32],
    domain: Domain,
    payload: Payload,
    key_id: &'static str,
    secret_key_keccak: &'static str,
    signature_keccak: &'static str,
    /// Hex, split into lines.
    signature: &'static [&'static str],
}

impl Kat {
    fn signature_bytes(&self) -> Vec<u8> {
        hex::decode(self.signature.concat()).unwrap()
    }
}

const KATS: [Kat; 3] = [
    Kat {
        seed: [0x00; 32],
        sign_rng_seed: [0xa0; 32],
        domain: domains::MSG,
        payload: Payload::Empty,
        key_id: "ccebc3b9792bf47064912171abf2b3d35a00acd64cada906f590ca13c3c82645",
        secret_key_keccak: "0c980d9d4016da569d76eef7e488e6e2594a2918f2ea114cbada0ced4c50c52e",
        signature_keccak: "355041c194cbe9c37b31bcbd99a6c54bf73bbd49376b0208264c9e35690f8ca2",
        signature: &[
        "39786dbf2aa7004c455e10ec4970f190191070d5b40241027202219caa4b69adadae6eb800b804c55bf89bfde6b9ebf6",
        "b8821bd416a2eab63a7bf3e63252eb801d379a5ad015f618a0534671b6e7523b7e04abe76f4657654349f6fab880098a",
        "d920156b79544e82f169ba8e283cd8a12b23f8f839e7ad292376eba53ee35bd4de14e324a3565cb051364970c34bf2eb",
        "e663de9acd79edf02d9a575b26b37413ac1afd610fa122d94f284f3c94d9b13aaf751d3f6c972a2da8acaf966f22e7f1",
        "a20dbf53751679bd25bdb51378455c85962cd14ef2ddcad6f8bb4b6639a66eb4f3c0dc02151597cb924d42d6ef7448b8",
        "2425a3f845311abd51ed404a5a0b90b7bd2c2752eb382b0d5545172a5d3c531ce8c0a394399abb5aa68023ad0e5121a2",
        "615e1d57fe00c76f1a72cf9a21410ada765a039fede162a8f8810bc66948490a4925791cb608cbe9fa2f6a9d1bda7530",
        "87bc768565c1667921e84d3eab13f7019bc9a24337263a60eb0719c267efe753d29c3436fb9e4876cf316aaa8617e619",
        "7dc6f006be4526f97c030b4edcd37191b296e8f7aca00e0102c51472a067b1aca1658202cf7e557489c83fab4952db93",
        "b93fa491d48dbb96a1088fa38ccf2b8f6e6cde1241a8bda1777bd52640566bf30d6faa5faa464e1853ead9a44c1324ac",
        "dfa464fe3c1976f0c9b8c8ff4a391b4af9d91e13ce15e23bb6575aa15290a587f325e493d48a21faf437c3c02522c963",
        "fdab4d9143d83f2a77327332b02d7e29e7475d59d9b2c13339d3d906870787b8706c9110e1ea0fdb67eeae0e7edb37be",
        "6f39864f893e4dacad7a0a9663cd54421773ffcd2ec28a1e443adbeeb59067e8c9998a18d67a6cdd2586a5c09606eada",
        "636db1a168c4128be26564b7612666f374592ad6475aeea7722c15349348010000000000000000000000",
        ],
    },
    Kat {
        seed: SEED_RAMP,
        sign_rng_seed: [0xa1; 32],
        domain: domains::KEY_ADD,
        payload: Payload::Text(b"hypersnap falcon kat 2"),
        key_id: "e0a67d0be8d4e596c8bdf59972733d63ecb042b07843fb93f4f75a81defca294",
        secret_key_keccak: "8e5dcd69b7729a30c3e8146921c05f2ed9b4898714e92688c161a7d7610425cc",
        signature_keccak: "c2389ca670ad994e62fbdaf32fde2b8d7e2fd3308961b47637c055bd7e5dacfd",
        signature: &[
        "39d09c05092212c7b0ed936b8401e55ee31fd717dd6e2a7d5b52fff57e6b530ce9ab60b21afbfc5a94ef4d383bd7463d",
        "0cd18df82218a9b7aab176db963f4909d570f166671f0c45c6c4fa7fd426c52de94e37572aebd0163b98a6839247bad9",
        "a97d236afdb37cd367f38cfa992cb7f15ef3bf05afca4e893ec31f27e707b3adc6d6713977ad125650518ecbb0562aa2",
        "6ef9b6cd8d481e19c2775936b74fe299560ae9dd720997d49280ddebf2f3de5d61371e76c2485e550e1fa1aae2ac4fd5",
        "f55672254d4142df4a883329a38539ad117070fa4a46dea2a437098eba342435226498b9c26829c954440c6974b1705e",
        "1c4d53187f9c49731bb6976a631537cd59d4349d69536cdb6eb5679d47ff09f1958a9512dc6b73bff62dfc3ab83186b7",
        "433035e30a9a53e44d5b1b5fffb261e757c322de4cf453f22629dcb8ff6d73d7083c8de1460ffe7be9511f87e51d6d88",
        "c629a5dc20b21672e47eaf9e72c1e4104687627609b0c6111e4751ffd0ce65e2b1a274fd665568e7a69e6a3f5a105d4f",
        "279c20bd6f823be5899e3b198676874c8f55798177d3fb5effb0de71da89d941405d2b4e64a24e36d8ddea981dd21177",
        "13fb6cdc16629e61db2e4c207ebb2cee2d2c12a15b096906a04a1430790fc5c7af1181ddfe58b1a867dfc246bbe16e0d",
        "f10f0bf19169633c2e1987a1c617bbf8bac19975afae9f6d8860233c2c245362298e0d599ff680c97ce84e3124cae46f",
        "fe522b670fb4ad54b241e4f67ba7b4de772847f26dc830e457864e2678b92887442d8db4e712b1344b546692174e8b56",
        "846d329ba5903b756cb920558948fa26ecbe609b300167d8aaef02597ee96ad4032efe11cfad4077dfcdb872faf4152b",
        "222eef2192cb22df37767684ac03ed954b0ed553da7e4911afd6a7c10ca55e0900000000000000000000",
        ],
    },
    Kat {
        seed: [0xff; 32],
        sign_rng_seed: [0xa2; 32],
        domain: domains::NODE_ATTESTATION_POP,
        payload: Payload::Ramp1000,
        key_id: "97947430e1091e6e90908e180fa30deb0e2cdfcaf98e6b9df4cb810a86f35595",
        secret_key_keccak: "760307901c183bbb14a89ea02b469d500da84dc60f81431ee9c967fbb81db2e3",
        signature_keccak: "1c467bff6fe18b8dd28a5c1f9ed6050f283f8c6d7d80596b25278901b79396d2",
        signature: &[
        "395d527a7aff7e0cc03a687c68f60e5f8030a9a82b3ed9a995bfd2834d1e1ffa155b33d724ab23b43a27b41e53cbe605",
        "e7ea3a90cbcf0be2ce6943693b6c9ce3690b3d95d046a973064d9c754df21869991d83b2f2a77b6205829b7b1dd694a3",
        "8b6ac6f974c2c80e3da72176fdc94f3cac93f0b73a61858d800ea3fbfab4dc1e6f69b0c6f34e426e2be589cafbbf4bef",
        "538852e3e7fd10f158fb2fa2d243877d9621dd0e1b63944baeb90a5a3c11cf2a9d6275a084d78d04a43129a26878a788",
        "aa07e5ed9e2c8453f974a94ec65c51a9542762d8705f730bf4ea79deee11ac735c849ee93c153754290d9ce8c141cf44",
        "4e3d2fe1639bd674770fa78e157afdf8e41476f66da2f3bf668ea140a103b5f951d60d7f074e33ebaa10ac90285941da",
        "0d6de35dd5b94d3f25f044e7dac1faf991ab8e9916b8e6f9d3b6c9f22d1c734cb1d5939cefafa80d66e89b80d855e5da",
        "17e7b0f4d726ef18173c5c2c5a6e65c19364fa755c104ee53c3f1833d7a1da0d2354d64135daafe1f869b67e3027a84e",
        "571cafdc805c26b6f7a3851623c7575c7cbdb51977e6e6bbf6aef7df13979e88274216d5150eb04285334ef121c082fa",
        "8d600e974addcf90aba850fe179991e4ee2ec17c9d659a87493a50498c2b7a06fd95324cc387397d906f8ed7fecab2cf",
        "5e769bf2b979497105faa38c05a2735efd7fdabe2a1c66c8ba3dcad2808956f957c104583e98a10d84b4ddb434ec3fa1",
        "c6d771cf2540f3287c6091dc934df0c734493bcc9d17c26542a52c5ccab00c04e0529dca716f5cea39095dceea94c6be",
        "804ec8336a54a2a44af3cd9667a19cd876bb49377dc3c4f5cf8f66a9176feff324dcd491c7c260846e793ff463509c9f",
        "6cb63b812d33c7334314aaa96245359fe2589d994b89387a359175837d24000000000000000000000000",
        ],
    },
];

#[test]
fn kat_key_ids() {
    for (i, kat) in KATS.iter().enumerate() {
        let sk = keygen_from_seed(kat.seed);
        assert_eq!(
            hex::encode(sk.public_key().key_id()),
            kat.key_id,
            "KAT {i}: key_id"
        );
        assert_eq!(
            hex::encode(hypersnap_falcon::key_id(sk.public_key())),
            kat.key_id,
            "KAT {i}: key_id()"
        );
        assert_eq!(
            hex::encode(keccak256(sk.as_bytes())),
            kat.secret_key_keccak,
            "KAT {i}: secret key"
        );
    }
}

#[test]
fn kat_signatures_verify() {
    for (i, kat) in KATS.iter().enumerate() {
        let sk = keygen_from_seed(kat.seed);
        let payload = kat.payload.bytes();
        let sig_bytes = kat.signature_bytes();
        assert_eq!(
            hex::encode(keccak256(&sig_bytes)),
            kat.signature_keccak,
            "KAT {i}"
        );
        let sig = FalconSignature::from_bytes(&sig_bytes).unwrap();
        verify(sk.public_key(), kat.domain, &payload, &sig).unwrap();
        verify_bytes(sk.public_key().as_bytes(), kat.domain, &payload, &sig_bytes).unwrap();
    }
}

#[test]
fn kat_signatures_fail_under_other_vectors() {
    for (i, kat) in KATS.iter().enumerate() {
        let sig = FalconSignature::from_bytes(&kat.signature_bytes()).unwrap();
        for (j, other) in KATS.iter().enumerate() {
            if i == j {
                continue;
            }
            let other_sk = keygen_from_seed(other.seed);
            // Other key, same domain and payload.
            assert_eq!(
                verify(
                    other_sk.public_key(),
                    kat.domain,
                    &kat.payload.bytes(),
                    &sig
                ),
                Err(FalconError::InvalidSignature)
            );
            // Same key, other domain and payload.
            let sk = keygen_from_seed(kat.seed);
            assert_eq!(
                verify(sk.public_key(), other.domain, &other.payload.bytes(), &sig),
                Err(FalconError::InvalidSignature)
            );
        }
    }
}

/// fn-dsa signing is hedged: the 40 RNG bytes are hashed with the secret key
/// and the message. With a seeded RNG, the signature is reproducible.
#[test]
fn kat_signing_is_deterministic_for_a_fixed_rng() {
    for (i, kat) in KATS.iter().enumerate() {
        let sk = keygen_from_seed(kat.seed);
        let mut rng = ChaCha20Rng::from_seed(kat.sign_rng_seed);
        let sig = sign(&sk, kat.domain, &kat.payload.bytes(), &mut rng).unwrap();
        assert_eq!(sig.as_bytes()[..], kat.signature_bytes()[..], "KAT {i}");
    }
}
