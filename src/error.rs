use thiserror::Error;

#[derive(Debug, Error)]
pub enum OtDspmError {
    #[error("capture error: {0}")]
    Capture(String),

    #[error("protocol parse error: {0}")]
    Parse(String),

    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("config error: {0}")]
    Config(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}
