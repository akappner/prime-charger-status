use aes::Aes128;
use cbc::{Decryptor, Encryptor};
use cipher::{block_padding::Pkcs7, BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};

type AesCbcEnc = Encryptor<Aes128>;
type AesCbcDec = Decryptor<Aes128>;

/// PKCS7-padded AES-128-CBC encrypt.
/// cipher 0.5 API: `encrypt_padded(buf, msg_len)` — buf must be pre-allocated
/// to the padded length.
pub fn aes_cbc_encrypt(key: &[u8; 16], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    let msg_len = plaintext.len();
    // PKCS7 always adds at least one byte; padded length = next multiple of 16.
    let padded_len = ((msg_len / 16) + 1) * 16;
    let mut buf = vec![0u8; padded_len];
    buf[..msg_len].copy_from_slice(plaintext);
    AesCbcEnc::new(key.into(), iv.into())
        .encrypt_padded::<Pkcs7>(&mut buf, msg_len)
        .expect("encrypt_padded should not fail with a correctly-sized buffer")
        .to_vec()
}

/// PKCS7-unpadded AES-128-CBC decrypt.
/// cipher 0.5 API: `decrypt_padded(buf)` — decrypts in-place, returns sub-slice.
pub fn aes_cbc_decrypt(
    key: &[u8; 16],
    iv: &[u8; 16],
    ciphertext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let mut buf = ciphertext.to_vec();
    AesCbcDec::new(key.into(), iv.into())
        .decrypt_padded::<Pkcs7>(&mut buf)
        .map(|b: &[u8]| b.to_vec())
        .map_err(|e| anyhow::anyhow!("AES-CBC decrypt error: {e:?}"))
}

/// Pad or truncate `src` to exactly 16 bytes (zero-padded on the right).
pub fn pad_iv(src: &[u8]) -> [u8; 16] {
    let mut iv = [0u8; 16];
    let n = src.len().min(16);
    iv[..n].copy_from_slice(&src[..n]);
    iv
}

// ── Crypto state machine ──────────────────────────────────────────────────────

/// Tracks the three lifecycle stages of the AES session:
///   `None` → `Initial` (after S/N extracted) → `Session` (after key exchange).
#[derive(Debug, Clone)]
pub enum CryptoKeys {
    /// Handshake not yet started.
    None,
    /// Plain handshake done; initial key = INITIAL_KEY, IV = pad_iv(serial).
    Initial { key: [u8; 16], iv: [u8; 16] },
    /// Session key exchanged with the device.
    Session { key: [u8; 16], iv: [u8; 16] },
}

impl CryptoKeys {
    pub fn key_iv(&self) -> Option<(&[u8; 16], &[u8; 16])> {
        match self {
            Self::Initial { key, iv } | Self::Session { key, iv } => Some((key, iv)),
            Self::None => None,
        }
    }

    pub fn is_session(&self) -> bool {
        matches!(self, Self::Session { .. })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [0u8; 16];
        let iv = [0u8; 16];
        let plaintext = b"hello world 1234";
        let ct = aes_cbc_encrypt(&key, &iv, plaintext);
        let pt = aes_cbc_decrypt(&key, &iv, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn pad_iv_short() {
        let iv = pad_iv(b"ABCD");
        assert_eq!(&iv[..4], b"ABCD");
        assert_eq!(&iv[4..], &[0u8; 12]);
    }

    #[test]
    fn pad_iv_long() {
        let iv = pad_iv(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        assert_eq!(&iv[..16], b"ABCDEFGHIJKLMNOP");
    }
}
