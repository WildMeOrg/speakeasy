//! Invitation format and everything derived from the invitation secret.
//!
//! The relay only ever sees the verifier (a public key) and sealed blobs.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub fn b64(b: &[u8]) -> String {
    STANDARD.encode(b)
}

pub fn unb64(s: &str) -> Result<Vec<u8>, String> {
    STANDARD.decode(s).map_err(|_| "bad base64".to_string())
}

pub fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("OS randomness unavailable");
    b
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Short fingerprint of a public key, for showing who sent a message.
pub fn fingerprint(key: &[u8]) -> String {
    hex(&Sha256::digest(key)[..8])
}

/// An invitation. Deliberately not a URL: nothing should ever navigate to it,
/// because a page served by the relay could then read the secret.
#[derive(Clone)]
pub struct Invite {
    pub relay: String,
    pub room: Uuid,
    pub secret: [u8; 32],
}

const INVITE_PREFIX: &str = "spk1.";

impl Invite {
    pub fn encode(&self) -> String {
        let mut raw = Vec::with_capacity(48 + self.relay.len());
        raw.extend_from_slice(self.room.as_bytes());
        raw.extend_from_slice(&self.secret);
        raw.extend_from_slice(self.relay.as_bytes());
        format!("{INVITE_PREFIX}{}", URL_SAFE_NO_PAD.encode(raw))
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        let body = s
            .trim()
            .strip_prefix(INVITE_PREFIX)
            .ok_or("not a speakeasy invitation")?;
        let raw = URL_SAFE_NO_PAD
            .decode(body)
            .map_err(|_| "invitation is not valid base64")?;
        if raw.len() <= 48 {
            return Err("invitation too short".into());
        }
        Ok(Invite {
            room: Uuid::from_slice(&raw[..16]).unwrap(),
            secret: raw[16..48].try_into().unwrap(),
            relay: String::from_utf8(raw[48..].to_vec()).map_err(|_| "bad relay address")?,
        })
    }
}

/// Keys derived from the invitation secret, one HKDF label each.
pub struct RoomKeys {
    pub room: Uuid,
    /// MLS external PSK: binds a join to the invitation, checked by members.
    pub psk: [u8; 32],
    /// Signs attach challenges; the relay holds only the public half.
    pub invite_key: SigningKey,
    info_key: [u8; 32],
    commit_key: [u8; 32],
}

pub enum Blob {
    GroupInfo,
    Commit,
}

impl RoomKeys {
    pub fn derive(room: &Uuid, secret: &[u8; 32]) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(room.as_bytes()), secret);
        let label = |l: &str| {
            let mut out = [0u8; 32];
            hk.expand(l.as_bytes(), &mut out).unwrap();
            out
        };
        RoomKeys {
            room: *room,
            psk: label("speakeasy/v1/mls-psk"),
            invite_key: SigningKey::from_bytes(&label("speakeasy/v1/relay-verifier")),
            info_key: label("speakeasy/v1/group-info"),
            commit_key: label("speakeasy/v1/external-commit"),
        }
    }

    pub fn verifier(&self) -> [u8; 32] {
        self.invite_key.verifying_key().to_bytes()
    }

    fn blob(&self, kind: &Blob) -> (&[u8; 32], Vec<u8>) {
        let (key, label) = match kind {
            Blob::GroupInfo => (&self.info_key, "group-info"),
            Blob::Commit => (&self.commit_key, "external-commit"),
        };
        let mut aad = label.as_bytes().to_vec();
        aad.extend_from_slice(self.room.as_bytes());
        (key, aad)
    }

    /// Hide a handshake blob from the relay. External commits and group info
    /// are public MLS messages that carry member names and keys.
    pub fn seal(&self, kind: Blob, plaintext: &[u8]) -> String {
        let (key, aad) = self.blob(&kind);
        let nonce: [u8; 24] = random();
        let ct = XChaCha20Poly1305::new(key.into())
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .expect("encryption cannot fail");
        b64(&[&nonce[..], &ct].concat())
    }

    pub fn open(&self, kind: Blob, sealed: &str) -> Result<Vec<u8>, String> {
        let raw = unb64(sealed)?;
        if raw.len() < 24 {
            return Err("sealed blob too short".into());
        }
        let (key, aad) = self.blob(&kind);
        XChaCha20Poly1305::new(key.into())
            .decrypt(
                &XNonce::try_from(&raw[..24]).unwrap(),
                Payload {
                    msg: &raw[24..],
                    aad: &aad,
                },
            )
            .map_err(|_| "blob was not sealed with this invitation".to_string())
    }
}

/// What gets signed to answer a relay challenge.
pub fn transcript(
    op: &str,
    room: &Uuid,
    nonce: &[u8],
    session_key: &[u8],
    cursor: u64,
) -> Vec<u8> {
    let mut t = b"speakeasy/v1/challenge\0".to_vec();
    t.extend_from_slice(op.as_bytes());
    t.push(0);
    t.extend_from_slice(room.as_bytes());
    t.extend_from_slice(nonce);
    t.extend_from_slice(session_key);
    t.extend_from_slice(&cursor.to_be_bytes());
    t
}

pub fn sign(key: &SigningKey, msg: &[u8]) -> String {
    b64(&key.sign(msg).to_bytes())
}

pub fn verify(key: &[u8], msg: &[u8], sig_b64: &str) -> bool {
    let Ok(key) = <[u8; 32]>::try_from(key) else {
        return false;
    };
    let Ok(key) = VerifyingKey::from_bytes(&key) else {
        return false;
    };
    let Ok(sig) = unb64(sig_b64) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(&sig) else {
        return false;
    };
    key.verify_strict(msg, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invite_round_trips_and_keys_are_bound_to_room_and_kind() {
        let inv = Invite {
            relay: "ws://127.0.0.1:1".into(),
            room: Uuid::new_v4(),
            secret: random(),
        };
        let back = Invite::parse(&inv.encode()).unwrap();
        assert_eq!((back.room, back.secret, &back.relay), (inv.room, inv.secret, &inv.relay));
        assert!(Invite::parse("https://relay/r/x#y").is_err());

        let k = RoomKeys::derive(&inv.room, &inv.secret);
        let sealed = k.seal(Blob::Commit, b"hello");
        assert_eq!(k.open(Blob::Commit, &sealed).unwrap(), b"hello");
        assert!(k.open(Blob::GroupInfo, &sealed).is_err());
        let other = RoomKeys::derive(&Uuid::new_v4(), &inv.secret);
        assert!(other.open(Blob::Commit, &sealed).is_err());

        let t = transcript("attach", &inv.room, &[1; 32], &[2; 32], 0);
        let sig = sign(&k.invite_key, &t);
        assert!(verify(&k.verifier(), &t, &sig));
        assert!(!verify(&other.verifier(), &t, &sig));
    }
}
