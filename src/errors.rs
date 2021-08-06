use std::error::Error;
use std::fmt::Debug;

use displaydoc::Display;

#[derive(Clone, Debug, Display)]
pub enum OpeError {
    /// Occurs when an invalid input is supplied for encryption
    InvalidInputError,
}

impl Error for OpeError {}
