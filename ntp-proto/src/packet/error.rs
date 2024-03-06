use std::fmt::Display;

use super::NtpPacket;

#[derive(Debug)]
pub enum ParsingError<T> {
    InvalidVersion(u8),
    IncorrectLength,
    MalformedNtsExtensionFields,
    MalformedNonce,
    MalformedCookiePlaceholder,
    DecryptError(T),
    #[cfg(feature = "ntpv5")]
    V5(super::v5::V5Error),
}

impl<T> ParsingError<T> {
    pub(super) fn get_decrypt_error<U>(self) -> Result<T, ParsingError<U>> {
        use ParsingError::*;

        match self {
            InvalidVersion(v) => Err(InvalidVersion(v)),
            IncorrectLength => Err(IncorrectLength),
            MalformedNtsExtensionFields => Err(MalformedNtsExtensionFields),
            MalformedNonce => Err(MalformedNonce),
            MalformedCookiePlaceholder => Err(MalformedCookiePlaceholder),
            DecryptError(decrypt_error) => Ok(decrypt_error),
            #[cfg(feature = "ntpv5")]
            V5(e) => Err(V5(e)),
        }
    }

    pub fn with_version(self, version: u8) -> VersionedParsingError<T> {
        VersionedParsingError {
            error: self,
            version: Some(version),
        }
    }

    pub fn without_version(self) -> VersionedParsingError<T> {
        VersionedParsingError {
            error: self,
            version: None,
        }
    }
}

impl ParsingError<std::convert::Infallible> {
    pub(super) fn generalize<U>(self) -> ParsingError<U> {
        use ParsingError::*;

        match self {
            InvalidVersion(v) => InvalidVersion(v),
            IncorrectLength => IncorrectLength,
            MalformedNtsExtensionFields => MalformedNtsExtensionFields,
            MalformedNonce => MalformedNonce,
            MalformedCookiePlaceholder => MalformedCookiePlaceholder,
            DecryptError(decrypt_error) => match decrypt_error {},
            #[cfg(feature = "ntpv5")]
            V5(e) => V5(e),
        }
    }

    pub(super) fn generalize_versioned<U>(self, version: u8) -> VersionedParsingError<U> {
        self.generalize().with_version(version)
    }
}

pub type PacketParsingError<'a> = ParsingError<NtpPacket<'a>>;

impl<T> Display for ParsingError<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidVersion(version) => f.write_fmt(format_args!("Invalid version {version}")),
            Self::IncorrectLength => f.write_str("Incorrect packet length"),
            Self::MalformedNtsExtensionFields => f.write_str("Malformed nts extension fields"),
            Self::MalformedNonce => f.write_str("Malformed nonce (likely invalid length)"),
            Self::MalformedCookiePlaceholder => f.write_str("Malformed cookie placeholder"),
            Self::DecryptError(_) => f.write_str("Failed to decrypt NTS extension fields"),
            #[cfg(feature = "ntpv5")]
            Self::V5(e) => Display::fmt(e, f),
        }
    }
}

impl<T: std::fmt::Debug> std::error::Error for ParsingError<T> {}

#[derive(Debug)]
pub struct VersionedParsingError<T> {
    pub error: ParsingError<T>,
    pub version: Option<u8>,
}

pub type VersionedPacketParsingError<'a> = VersionedParsingError<NtpPacket<'a>>;

impl<T> From<ParsingError<T>> for VersionedParsingError<T> {
    fn from(value: ParsingError<T>) -> Self {
        value.without_version()
    }
}

impl<T> Display for VersionedParsingError<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}

pub trait ParsingResultExt<T, E> {
    fn with_version(self, version: u8) -> Result<T, VersionedParsingError<E>>;
    fn without_version(self) -> Result<T, VersionedParsingError<E>>;
}

impl<T, E> ParsingResultExt<T, E> for Result<T, ParsingError<E>> {
    fn with_version(self, version: u8) -> Result<T, VersionedParsingError<E>> {
        match self {
            Ok(res) => Ok(res),
            Err(e) => Err(e.with_version(version)),
        }
    }

    fn without_version(self) -> Result<T, VersionedParsingError<E>> {
        match self {
            Ok(res) => Ok(res),
            Err(e) => Err(e.without_version()),
        }
    }
}

impl<T: std::fmt::Debug> std::error::Error for VersionedParsingError<T> {}
