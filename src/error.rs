use std::io;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("config error: {0}")]
    Config(String),

    #[error("parse error: {0}")]
    Parse(String),

    #[error("interface {name} not found")]
    InterfaceNotFound { name: String },

    #[error("invalid packet: {0}")]
    InvalidPacket(String),
}

pub type Result<T> = std::result::Result<T, Error>;
