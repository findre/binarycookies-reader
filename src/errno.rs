use std::{fmt::Display, error::Error, io::Error as IoError};

#[derive(Debug)]
pub enum BinaryCookieError {
    InvalidSignature,
    InvalidStartCode,
    EndCodeError,
    EndHeaderCodeError,
    DataOverSize,
    SystemIOError(IoError)
}

impl Error for BinaryCookieError {}

impl Display for BinaryCookieError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BinaryCookieError::InvalidSignature => write!(f, "signature code is invalid, need 'cook'"),
            BinaryCookieError::InvalidStartCode => write!(f, "start code is invalid, except '0010'"),
            BinaryCookieError::EndCodeError => write!(f, "end code is invalid, need '0000'"),
            BinaryCookieError::EndHeaderCodeError => write!(f, "end header code not allow, need '0000'"),
            BinaryCookieError::DataOverSize => write!(f, "data size over size"),
            BinaryCookieError::SystemIOError(err) => write!(f, "{}", err)
        }
    }
}

impl From<std::io::Error> for BinaryCookieError {
    fn from(value: IoError) -> Self {
        BinaryCookieError::SystemIOError(value)
    }
}
