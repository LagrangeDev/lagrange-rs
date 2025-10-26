use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Service not found: {0}")]
    ServiceNotFound(String),

    #[error("Context not initialized")]
    ContextNotInitialized,

    #[error("Protocol error: {0}")]
    ProtocolError(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Build error: {0}")]
    BuildError(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Other error: {0}")]
    Other(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
