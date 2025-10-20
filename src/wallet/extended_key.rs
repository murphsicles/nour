//! BIP-32 extended keys for Bitcoin SV wallets (xpub/xprv).

use crate::network::Network;
use crate::util::{Error, Result, Serializable};
use base58::{ToBase58, FromBase58};
use bitcoin_hashes::hmac::{Hmac, HmacEngine, Mac}; // Use bitcoin_hashes for HMAC_SHA512
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use std::io::{self, Read, Write};
use std::fmt;

#[cfg(feature = "async")]
use tokio::io::{AsyncRead, AsyncWrite};

// Version bytes for extended keys
pub const MAINNET_PRIVATE_EXTENDED_KEY: [u8; 4] = [0x04, 0x88, 0xAD, 0xE4]; // xprv
pub const MAINNET_PUBLIC_EXTENDED_KEY: [u8; 4] = [0x04, 0x88, 0xB2, 0x1E]; // xpub
pub const TESTNET_PRIVATE_EXTENDED_KEY: [u8; 4] = [0x04, 0x35, 0x83, 0x94]; // tprv
pub const TESTNET_PUBLIC_EXTENDED_KEY: [u8; 4] = [0x04, 0x35, 0x87, 0xCF]; // tpub
pub const HARDENED_KEY: u32 = 0x80000000;

/// Type of extended key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtendedKeyType {
    Private,
    Public,
}

/// Represents a BIP-32 extended key (private or public).
#[derive(Clone, PartialEq, Eq)]
pub struct ExtendedKey(pub [u8; 78]);

impl ExtendedKey {
    /// Returns the version bytes.
    #[must_use]
    #[inline]
    pub fn version(&self) -> [u8; 4] {
        let mut version = [0u8; 4];
        version.copy_from_slice(&self.0[0..4]);
        version
    }

    /// Returns the depth of the key.
    #[must_use]
    #[inline]
    pub fn depth(&self) -> u8 {
        self.0[4]
    }

    /// Returns the parent fingerprint.
    #[must_use]
    #[inline]
    pub fn parent_fingerprint(&self) -> [u8; 4] {
        let mut fingerprint = [0u8; 4];
        fingerprint.copy_from_slice(&self.0[5..9]);
        fingerprint
    }

    /// Returns the child number.
    #[must_use]
    #[inline]
    pub fn child_number(&self) -> u32 {
        u32::from_be_bytes(self.0[9..13].try_into().unwrap())
    }

    /// Returns the chain code.
    #[must_use]
    #[inline]
    pub fn chain_code(&self) -> [u8; 32] {
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&self.0[13..45]);
        chain_code
    }

    /// Returns the key data (private key or public key).
    #[must_use]
    #[inline]
    pub fn key(&self) -> [u8; 33] {
        let mut key = [0u8; 33];
        key.copy_from_slice(&self.0[45..78]);
        key
    }

    /// Checks if the key is private.
    #[must_use]
    #[inline]
    pub fn is_private(&self) -> bool {
        let version = self.version();
        version == MAINNET_PRIVATE_EXTENDED_KEY || version == TESTNET_PRIVATE_EXTENDED_KEY
    }

    /// Encodes an extended key into a base58 string.
    #[must_use]
    pub fn encode(&self) -> String {
        let checksum = bh_sha256d::Hash::hash(&self.0).to_byte_array();
        let mut v = [0u8; 82];
        v[0..78].copy_from_slice(&self.0);
        v[78..82].copy_from_slice(&checksum[0..4]);
        v.to_base58()
    }

    /// Decodes an extended key from a base58 string.
    ///
    /// # Errors
    /// `Error::BadData` if invalid length or checksum.
    pub fn decode(s: &str) -> Result<ExtendedKey> {
        let v = s.from_base58().map_err(|e| Error::FromBase58Error(e))?;
        if v.len() != 82 {
            return Err(Error::BadData("Invalid extended key length".to_string()));
        }
        let checksum = bh_sha256d::Hash::hash(&v[..78]).to_byte_array();
        if checksum[0..4] != v[78..] {
            return Err(Error::BadData("Invalid checksum".to_string()));
        }
        let mut extended_key = ExtendedKey([0; 78]);
        extended_key.0.copy_from_slice(&v[..78]);
        Ok(extended_key)
    }

    /// Derives a child key (hardened or normal).
    ///
    /// # Errors
    /// `Error::BadData` if invalid lengths or tweak fails.
    pub fn derive_child(&self, index: u32, secp: &Secp256k1<secp256k1::All>) -> Result<ExtendedKey> {
        let is_private = self.is_private();
        let is_hardened = index >= HARDENED_KEY;

        let mut hmac_input = Vec::with_capacity(37);
        if is_private {
            hmac_input.push(0);
            let private_key = &self.key()[1..33];
            if private_key.len() != 32 {
                return Err(Error::BadData(format!("Invalid private key length: {}", private_key.len())));
            }
            hmac_input.extend_from_slice(private_key);
        } else {
            if is_hardened {
                return Err(Error::InvalidOperation("Hardened derivation not supported for public keys".to_string()));
            }
            hmac_input.extend_from_slice(&self.key());
        }
        hmac_input.extend_from_slice(&index.to_be_bytes());

        let chain_code = self.chain_code();
        let mut hmac_engine = HmacEngine::<sha512::Hash>::new(&chain_code);
        hmac_engine.update(&hmac_input);
        let result = hmac_engine.finalize().into_bytes();
        if result.len() != 64 {
            return Err(Error::BadData(format!("Invalid HMAC output length: {}", result.len())));
        }
        let il = &result[0..32];
        let new_chain_code = &result[32..64];

        let mut child_key = ExtendedKey([0; 78]);
        child_key.0[0..4].copy_from_slice(&self.version());
        child_key.0[4] = self.depth().wrapping_add(1);
        let parent_pubkey = if is_private {
            let private_key = &self.key()[1..33];
            let secret_key = SecretKey::from_slice(private_key)?;
            PublicKey::from_secret_key(secp, &secret_key)
        } else {
            PublicKey::from_slice(&self.key())?
        };
        let fingerprint = bh_sha256d::Hash::hash(&parent_pubkey.serialize()).to_byte_array();
        child_key.0[5..9].copy_from_slice(&fingerprint[0..4]);
        child_key.0[9..13].copy_from_slice(&index.to_be_bytes());
        child_key.0[13..45].copy_from_slice(new_chain_code);

        if is_private {
            let private_key = &self.key()[1..33];
            let secret_key = SecretKey::from_slice(private_key)?;
            let tweak = SecretKey::from_slice(il)?;
            let child_secret = secret_key.add_tweak(&tweak.into())?;
            child_key.0[45] = 0; // Private prefix
            child_key.0[46..78].copy_from_slice(&child_secret[..]);
        } else {
            let pubkey = PublicKey::from_slice(&self.key())?;
            let tweak = SecretKey::from_slice(il)?;
            let child_pubkey = pubkey.add_exp_tweak(secp, &tweak.into())?;
            child_key.0[45..78].copy_from_slice(&child_pubkey.serialize());
        }

        Ok(child_key)
    }
}

impl Serializable<ExtendedKey> for ExtendedKey {
    fn read(reader: &mut dyn Read) -> Result<ExtendedKey> {
        let mut data = [0u8; 78];
        reader.read_exact(&mut data).map_err(|e| Error::IOError(e))?;
        Ok(ExtendedKey(data))
    }

    fn write(&self, writer: &mut dyn Write) -> io::Result<()> {
        writer.write_all(&self.0)
    }
}

impl fmt::Debug for ExtendedKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ExtendedKey({})", self.encode())
    }
}

/// Derives an extended key from a seed or parent key.
pub fn derive_extended_key(
    input: &str,
    path: &str,
    network: Network,
    secp: &Secp256k1<secp256k1::All>,
) -> Result<ExtendedKey> {
    if path.is_empty() || path == "m" {
        let seed = hex::decode(input).map_err(|_| Error::BadData("Invalid hex seed".to_string()))?;
        return extended_key_from_seed(&seed, network);
    }

    let mut key = ExtendedKey::decode(input)?;
    let path_parts: Vec<&str> = path.trim_start_matches("m/").split('/').collect();
    for part in path_parts {
        let is_hardened = part.ends_with('H') || part.ends_with('\'');
        let index_str = part.trim_end_matches(|c| c == 'H' || c == '\'');
        let index: u32 = index_str
            .parse()
            .map_err(|_| Error::BadData("Invalid derivation index".to_string()))?;
        let index = if is_hardened { index + HARDENED_KEY } else { index };
        key = key.derive_child(index, secp)?;
    }
    Ok(key)
}

/// Creates an extended private key from a seed.
pub fn extended_key_from_seed(seed: &[u8], network: Network) -> Result<ExtendedKey> {
    let mut hmac_engine = HmacEngine::<sha256d::Hash>::new(b"Bitcoin seed");
    hmac_engine.update(seed);
    let result = hmac_engine.finalize().into_inner();
    if result.len() != 64 {
        return Err(Error::BadData(format!("Invalid HMAC output length: {}", result.len())));
    }

    let il = &result[0..32];
    let chain_code = &result[32..64];
    let secret_key = SecretKey::from_slice(il)?;

    let mut key = ExtendedKey([0; 78]);
    let version = match network {
        Network::Mainnet => MAINNET_PRIVATE_EXTENDED_KEY,
        Network::Testnet | Network::STN => TESTNET_PRIVATE_EXTENDED_KEY,
    };
    key.0[0..4].copy_from_slice(&version);
    key.0[4] = 0; // depth
    key.0[5..9].copy_from_slice(&[0; 4]); // parent fingerprint
    key.0[9..13].copy_from_slice(&[0; 4]); // child number
    key.0[13..45].copy_from_slice(chain_code);
    key.0[45] = 0; // private prefix
    key.0[46..78].copy_from_slice(&secret_key[..]);

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_hmac() -> Result<()> {
        let key = hex::decode("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508")?;
        let private_key = [
            232, 243, 46, 114, 61, 236, 244, 5, 26, 239, 172, 142, 44, 147, 201, 197,
            178, 20, 49, 56, 23, 205, 176, 26, 20, 148, 185, 23, 200, 67, 107, 53,
        ];
        let index = 0x80000000u32;
        let mut data = vec![0u8; 37];
        data[0] = 0;
        data[1..33].copy_from_slice(&private_key[..32]);
        data[33..37].copy_from_slice(&index.to_be_bytes());

        let mut hmac_engine = HmacEngine::<sha256d::Hash>::new(&key);
        hmac_engine.update(&data);
        let result = hmac_engine.finalize().into_inner();
        assert_eq!(
            hex::encode(result),
            "04bfb2dd60fa8921c2a4085ec15507a921f49cdc839f27f0f280e9c1495d44b547fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141"
        );
        Ok(())
    }

    #[test]
    fn test_encode_decode() -> Result<()> {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f")?;
        let key = extended_key_from_seed(&seed, Network::Testnet)?;
        let encoded = key.encode();
        let decoded = ExtendedKey::decode(&encoded)?;
        assert_eq!(key, decoded);
        Ok(())
    }

    #[test]
    fn test_path() -> Result<()> {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f")?;
        let master = extended_key_from_seed(&seed, Network::Testnet)?;
        let secp = Secp256k1::new();

        let child = master.derive_child(HARDENED_KEY, &secp)?; // m/0H
        let encoded = child.encode();
        assert_eq!(
            encoded,
            "tprv8dRs2KikLW2c37FPa3Vxkefo3x8zENMRVfCuDUYRoM9zGG1EDh4cUM6TxM58uWDp76on4HdnWUrFrRNYK2Xhhq4gP5RV5CozT2iUMTquXEy"
        );
        Ok(())
    }

    #[test]
    fn test_pubkey() -> Result<()> {
        let secp = Secp256k1::new();
        let private_key = hex::decode("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35")?;
        let secret_key = SecretKey::from_slice(&private_key)?;
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        assert_eq!(hex::encode(public_key.serialize()), "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2");
        Ok(())
    }
}
