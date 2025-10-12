//! BIP-39 mnemonic encoding/decoding for Bitcoin SV wallet seed phrases.

use crate::util::{Bits, Error, Result};
use bitcoin_hashes::sha256 as bh_sha256;
use std::str;

/// Wordlist language.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wordlist {
    ChineseSimplified,
    ChineseTraditional,
    English,
    French,
    Italian,
    Japanese,
    Korean,
    Spanish,
}

/// Maximum data length for mnemonic encoding (512 bits, BIP-39 standard).
const MAX_DATA_LEN: usize = 512 / 8;

/// Loads the word list for a given language (2048 words).
///
/// # Panics
/// If wordlist file is invalid UTF-8 or not 2048 words.
pub fn load_wordlist(wordlist: Wordlist) -> &'static [String] {
    static CHINESE_SIMPLIFIED: &[String; 2048] = &load_wordlist_internal(include_bytes!("wordlists/chinese_simplified.txt"));
    static CHINESE_TRADITIONAL: &[String; 2048] = &load_wordlist_internal(include_bytes!("wordlists/chinese_traditional.txt"));
    static ENGLISH: &[String; 2048] = &load_wordlist_internal(include_bytes!("wordlists/english.txt"));
    static FRENCH: &[String; 2048] = &load_wordlist_internal(include_bytes!("wordlists/french.txt"));
    static ITALIAN: &[String; 2048] = &load_wordlist_internal(include_bytes!("wordlists/italian.txt"));
    static JAPANESE: &[String; 2048] = &load_wordlist_internal(include_bytes!("wordlists/japanese.txt"));
    static KOREAN: &[String; 2048] = &load_wordlist_internal(include_bytes!("wordlists/korean.txt"));
    static SPANISH: &[String; 2048] = &load_wordlist_internal(include_bytes!("wordlists/spanish.txt"));

    match wordlist {
        Wordlist::ChineseSimplified => CHINESE_SIMPLIFIED,
        Wordlist::ChineseTraditional => CHINESE_TRADITIONAL,
        Wordlist::English => ENGLISH,
        Wordlist::French => FRENCH,
        Wordlist::Italian => ITALIAN,
        Wordlist::Japanese => JAPANESE,
        Wordlist::Korean => KOREAN,
        Wordlist::Spanish => SPANISH,
    }
}

fn load_wordlist_internal(bytes: &[u8]) -> [String; 2048] {
    let text = str::from_utf8(bytes).expect("Invalid UTF-8 wordlist");
    let words: Vec<String> = text.lines().map(|s| s.to_string()).collect();
    if words.len() != 2048 {
        panic!("Wordlist must have exactly 2048 words");
    }
    words.try_into().unwrap_or_else(|_| panic!("Wordlist conversion failed"))
}

/// Encodes data into a mnemonic using BIP-39.
///
/// # Errors
/// `Error::BadData` if data length > MAX_DATA_LEN or not a multiple of 4 bytes.
pub fn mnemonic_encode(data: &[u8], word_list: &[String]) -> Result<Vec<String>> {
    if data.len() > MAX_DATA_LEN {
        return Err(Error::BadData(format!("Data too long: {}", data.len())));
    }
    if data.len() % 4 != 0 || data.is_empty() {
        return Err(Error::BadData("Data length must be multiple of 4 bytes".to_string()));
    }
    let hash = bh_sha256::Hash::hash(data);
    let cs_len = data.len() / 4;
    let word_count = (data.len() * 8 + cs_len) / 11;
    let mut words = Vec::with_capacity(word_count);
    let mut bits = Bits::from_slice(data, data.len() * 8);
    bits.append(&Bits::from_slice(hash.as_ref(), cs_len));
    for i in 0..word_count {
        let index = bits.extract(i * 11, 11) as usize;
        words.push(word_list.get(index).ok_or_else(|| Error::BadData("Invalid bit index".to_string()))?.clone());
    }
    Ok(words)
}

/// Decodes a mnemonic into data using BIP-39.
///
/// # Errors
/// `Error::BadArgument` if invalid word, length, or checksum.
pub fn mnemonic_decode(mnemonic: &[String], word_list: &[String]) -> Result<Vec<u8>> {
    if mnemonic.is_empty() {
        return Ok(Vec::new());
    }
    if mnemonic.len() * 11 % 33 != 0 {
        return Err(Error::BadArgument(format!("Invalid mnemonic length: {}", mnemonic.len())));
    }
    let mut bits = Bits::with_capacity(mnemonic.len() * 11);
    for word in mnemonic {
        let value = word_list
            .iter()
            .position(|w| w == word)
            .ok_or_else(|| Error::BadArgument(format!("Bad word: {}", word)))?;
        let word_bits = Bits::from_slice(&[(value >> 3) as u8, ((value & 7) as u8) << 5], 11);
        bits.append(&word_bits);
    }
    let data_len = bits.len * 32 / 33;
    let cs_len = bits.len / 33;
    let hash = bh_sha256::Hash::hash(&bits.data[0..data_len / 8]);
    let cs_bits = Bits::from_slice(hash.as_ref(), cs_len);
    if cs_bits.extract(0, cs_len) != bits.extract(data_len, cs_len) {
        return Err(Error::BadArgument("Invalid checksum".to_string()));
    }
    Ok(bits.data[0..data_len / 8].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;
    use pretty_assertions::assert_eq;

    #[test]
    fn wordlists() {
        assert_eq!(load_wordlist(Wordlist::ChineseSimplified).len(), 2048);
        assert_eq!(load_wordlist(Wordlist::ChineseTraditional).len(), 2048);
        assert_eq!(load_wordlist(Wordlist::English).len(), 2048);
        assert_eq!(load_wordlist(Wordlist::French).len(), 2048);
        assert_eq!(load_wordlist(Wordlist::Italian).len(), 2048);
        assert_eq!(load_wordlist(Wordlist::Japanese).len(), 2048);
        assert_eq!(load_wordlist(Wordlist::Korean).len(), 2048);
        assert_eq!(load_wordlist(Wordlist::Spanish).len(), 2048);
    }

    #[test]
    fn encode_decode() {
        let data = (0..16).collect::<Vec<u8>>();
        let wordlist = load_wordlist(Wordlist::English);
        let mnemonic = mnemonic_encode(&data, &wordlist).unwrap();
        assert_eq!(mnemonic_decode(&mnemonic, &wordlist).unwrap(), data);
    }

    #[test]
    fn invalid() {
        let wordlist = load_wordlist(Wordlist::English);
        assert!(mnemonic_encode(&[], &wordlist).is_err());
        assert_eq!(mnemonic_decode(&[], &wordlist).unwrap(), vec![]);

        let data = (0..16).collect::<Vec<u8>>();
        let mnemonic = mnemonic_encode(&data, &wordlist).unwrap();
        let mut bad_checksum = mnemonic.clone();
        bad_checksum[0] = "hello".to_string();
        assert_eq!(mnemonic_decode(&bad_checksum, &wordlist).unwrap_err().to_string(), "Bad word: hello");

        let mut bad_word = mnemonic.clone();
        bad_word[0] = "123".to_string();
        assert_eq!(mnemonic_decode(&bad_word, &wordlist).unwrap_err().to_string(), "Bad word: 123");
    }

    #[test]
    fn test_vectors() {
        let wordlist = load_wordlist(Wordlist::English);

        let vectors = [
            ("00000000000000000000000000000000", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"),
            ("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", "legal winner thank year wave sausage worth useful legal winner thank yellow"),
            ("80808080808080808080808080808080", "letter advice cage absurd amount doctor acoustic avoid letter advice cage above"),
            ("ffffffffffffffffffffffffffffffff", "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"),
            ("000000000000000000000000000000000000000000000000", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent"),
            ("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will"),
            ("808080808080808080808080808080808080808080808080", "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always"),
            ("ffffffffffffffffffffffffffffffffffffffffffffffff", "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when"),
            ("0000000000000000000000000000000000000000000000000000000000000000", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"),
            ("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title"),
            ("8080808080808080808080808080808080808080808080808080808080808080", "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless"),
            ("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote"),
            ("9e885d952ad362caeb4efe34a8e91bd2", "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic"),
            ("6610b25967cdcca9d59875f5cb50b0ea75433311869e930b", "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog"),
            ("68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c", "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length"),
            ("c0ba5a8e914111210f2bd131f3d5e08d", "scheme spot photo card baby mountain device kick cradle pact join borrow"),
            ("6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3", "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave"),
            ("9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863", "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside"),
            ("23db8160a31d3e0dca3688ed941adbf3", "cat swing flag economy stadium alone churn speed unique patch report train"),
            ("8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0", "light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access"),
            ("066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad", "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform"),
            ("f30f8c1da665478f49b001d94c5fc452", "vessel ladder alter error federal sibling chat ability sun glass valve picture"),
            ("c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05", "scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump"),
            ("f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f", "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold"),
        ];

        for (hex, expected) in vectors {
            let data = hex::decode(hex).unwrap();
            let mnemonic = mnemonic_encode(&data, &wordlist).unwrap().join(" ");
            assert_eq!(mnemonic, expected);
            assert_eq!(mnemonic_decode(&expected.split(' ').map(String::from).collect::<Vec<_>>(), &wordlist).unwrap(), data);
        }
    }
}
