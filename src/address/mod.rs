//! Address handling for Bitcoin SV: P2PKH and P2SH encoding/decoding in base58check format.
//!
//! Supports Mainnet, Testnet, and STN networks with checksum verification using double-SHA256.
/// Payload must be exactly 20 bytes (Hash160). Optimized for high-throughput applications.

use base58::{ToBase58, FromBase58};
use crate::util::{Error, Result, sha256d};
use crate::network::Network;

const MAINNET_P2PKH_VERSION: u8 = 0x00;
const MAINNET_P2SH_VERSION: u8 = 0x05;
const TESTNET_P2PKH_VERSION: u8 = 0x6F;
const TESTNET_P2SH_VERSION: u8 = 0xC4;

/// Encodes a base58check address from version byte and 20-byte payload.
///
/// # Errors
/// Returns `Error::BadArgument` if payload is not exactly 20 bytes.
///
/// # Examples
/// ```
/// use nour::address::encode_address;
/// use nour::network::Network;
/// let addr = encode_address(Network::Mainnet, 0x00, &[0u8; 20]).unwrap();
/// assert_eq!(addr, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
/// ```
#[must_use]
#[inline]
pub fn encode_address(_network: Network, version: u8, payload: &[u8]) -> Result<String> {
    if payload.len() != 20 {
        return Err(Error::BadArgument("Payload must be 20 bytes".to_string()));
    }
    // Use fixed-size array for zero-allocation efficiency
    let mut v = [0u8; 25];
    v[0] = version;
    v[1..21].copy_from_slice(payload);
    let checksum = sha256d(&v[..21]);
    v[21..25].copy_from_slice(&checksum.0[..4]);
    Ok(v.to_base58())
}

/// Decodes a base58check address into version and payload.
///
/// Verifies 25-byte length and checksum; extracts version (byte 0) and payload (bytes 1-20).
///
/// # Errors
/// Returns `Error::FromBase58Error` on decode failure, `Error::BadData` on invalid length/checksum.
///
/// # Examples
/// ```
/// use nour::address::decode_address;
/// let (version, payload) = decode_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").unwrap();
/// assert_eq!(version, 0x00);
/// assert_eq!(payload, vec![0u8; 20]);
/// ```
#[must_use]
#[inline]
pub fn decode_address(input: &str) -> Result<(u8, Vec<u8>)> {
    let bytes = input.from_base58().map_err(|e| Error::FromBase58Error(e))?;
    if bytes.len() != 25 {
        return Err(Error::BadData("Invalid address length".to_string()));
    }
    let checksum = sha256d(&bytes[..21]);
    if checksum.0[..4] != bytes[21..] {
        return Err(Error::BadData("Invalid checksum".to_string()));
    }
    let version = bytes[0];
    let payload = bytes[1..21].to_vec();
    Ok((version, payload))
}

/// Encodes a P2PKH address from 20-byte pubkey hash.
#[must_use]
#[inline]
pub fn encode_p2pkh_address(network: Network, pubkey_hash: &[u8]) -> Result<String> {
    let version = match network {
        Network::Mainnet => MAINNET_P2PKH_VERSION,
        Network::Testnet | Network::STN => TESTNET_P2PKH_VERSION,
    };
    encode_address(network, version, pubkey_hash)
}

/// Encodes a P2SH address from 20-byte script hash.
#[must_use]
#[inline]
pub fn encode_p2sh_address(network: Network, script_hash: &[u8]) -> Result<String> {
    let version = match network {
        Network::Mainnet => MAINNET_P2SH_VERSION,
        Network::Testnet | Network::STN => TESTNET_P2SH_VERSION,
    };
    encode_address(network, version, script_hash)
}

/// Validates an address version against the network (P2PKH or P2SH only).
///
/// # Errors
/// Returns `Error::BadData` if version mismatches network.
#[must_use]
#[inline]
pub fn validate_address(network: Network, address: &str) -> Result<()> {
    let (version, _) = decode_address(address)?;
    let expected_version = match network {
        Network::Mainnet => [MAINNET_P2PKH_VERSION, MAINNET_P2SH_VERSION],
        Network::Testnet | Network::STN => [TESTNET_P2PKH_VERSION, TESTNET_P2SH_VERSION],
    };
    if !expected_version.contains(&version) {
        return Err(Error::BadData("Invalid address version for network".to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_encode_decode_p2pkh() -> Result<()> {
        let pubkey_hash: [u8; 20] = hex::decode("1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b")?
            .try_into()
            .map_err(|_| Error::BadData("Invalid pubkey hash".to_string()))?;
        let address = encode_p2pkh_address(Network::Mainnet, &pubkey_hash)?;
        assert_eq!(address, "13PNN3hx4wxHBLFwLNNwmKxD6V5jFZQo6s");
        let (version, decoded) = decode_address(&address)?;
        assert_eq!(version, MAINNET_P2PKH_VERSION);
        assert_eq!(decoded, pubkey_hash.to_vec());
        Ok(())
    }

    #[test]
    fn test_encode_decode_p2sh() -> Result<()> {
        let script_hash: [u8; 20] = hex::decode("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0")?
            .try_into()
            .map_err(|_| Error::BadData("Invalid script hash".to_string()))?;
        let address = encode_p2sh_address(Network::Testnet, &script_hash)?;
        let (version, decoded) = decode_address(&address)?;
        assert_eq!(version, TESTNET_P2SH_VERSION);
        assert_eq!(decoded, script_hash.to_vec());
        Ok(())
    }

    #[test]
    fn test_validate_address() -> Result<()> {
        let valid_mainnet = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        let valid_testnet = "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn";
        validate_address(Network::Mainnet, valid_mainnet)?;
        validate_address(Network::Testnet, valid_testnet)?;
        assert_eq!(validate_address(Network::Mainnet, valid_testnet).unwrap_err().to_string(), "Bad data: Invalid address version for network");
        Ok(())
    }
}
