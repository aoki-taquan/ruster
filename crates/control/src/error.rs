#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    #[error("validation failed: {0}")]
    Validation(String),

    #[error("nothing to commit: no running configuration")]
    NothingToCommit,
}
