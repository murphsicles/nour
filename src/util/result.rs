//! Standard error and result types for the library.
use base58::FromBase58Error;
use hex::FromHexError;
use secp256k1::Error as Secp256k1Error;
use std::io;
use std::num::ParseIntError;
use std::string::FromUtf8Error;

/// Standard error type used in the library
#[derive(Debug)]
pub enum Error {
    /// An argument provided is invalid
    BadArgument(String),
    /// The data given is not valid
    BadData(String),
    /// Base58 string could not be decoded
    FromBase58Error(FromBase58Error),
    /// Hex string could not be decoded
    FromHexError(FromHexError),
    /// UTF8 parsing error
    FromUtf8Error(FromUtf8Error),
    /// The state is not valid
    IllegalState(String),
    /// The operation is not valid on this object
    InvalidOperation(String),
    /// Standard library IO error
    IOError(io::Error),
    /// Error parsing an integer
    ParseIntError(ParseIntError),
    /// Error evaluating the script
    ScriptError(String),
    /// Error in the Secp256k1 library
    Secp256k1Error(Secp256k1Error),
    /// The operation timed out
    Timeout,
    /// The data or functionality is not supported by this library
    Unsupported(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::BadArgument(s) => write!(f, "Bad argument: {}", s),
            Error::BadData(s) => write!(f, "Bad data: {}", s),
            Error::FromBase58Error(e) => write!(f, "Base58 decoding error: {:?}", e),
            Error::FromHexError(e) => write!(f, "Hex decoding error: {}", e),
            Error::FromUtf8Error(e) => write!(f, "Utf8 parsing error: {}", e),
            Error::IllegalState(s) => write!(f, "Illegal state: {}", s),
            Error::InvalidOperation(s) => write!(f, "Invalid operation: {}", s),
            Error::IOError(e) => write!(f, "IO error: {}", e),
            Error::ParseIntError(e) => write!(f, "ParseIntError: {}", e),
            Error::ScriptError(s) => write!(f, "Script error: {}", s),
            Error::Secp256k1Error(e) => write!(f, "Secp256k1 error: {}", e),
            Error::Timeout => write!(f, "Timeout"),
            Error::Unsupported(s) => write!(f, "Unsupported: {}", s),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::FromHexError(e) => Some(e),
            Error::FromUtf8Error(e) => Some(e),
            Error::IOError(e) => Some(e),
            Error::ParseIntError(e) => Some(e),
            Error::Secp256k1Error(e) => Some(e),
            _ => None,
        }
    }
}

impl From<FromBase58Error> for Error {
    fn from(e: FromBase58Error) -> Self {
        Error::FromBase58Error(e)
    }
}

impl From<FromHexError> for Error {
    fn from(e: FromHexError) -> Self {
        Error::FromHexError(e)
    }
}

impl From<FromUtf8Error> for Error {
    fn from(e: FromUtf8Error) -> Self {
        Error::FromUtf8Error(e)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::IOError(e)
    }
}

impl From<ParseIntError> for Error {
    fn from(e: ParseIntError) -> Self {
        Error::ParseIntError(e)
    }
}

impl From<Secp256k1Error> for Error {
    fn from(e: Secp256k1Error) -> Self {
        Error::Secp256k1Error(e)
    }
}

/// Standard Result used in the library
pub type Result<T> = std::result::Result<T, Error>;
