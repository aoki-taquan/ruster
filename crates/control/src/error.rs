#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    #[error("validation failed: {0}")]
    Validation(String),

    #[error("nothing to commit: no running configuration")]
    NothingToCommit,

    #[error("transaction not validated: must call prepare() before commit")]
    TransactionNotValidated,

    #[error("transaction already consumed: cannot reuse a committed or aborted transaction")]
    TransactionAlreadyConsumed,

    #[error("nothing to rollback: no previous configuration snapshot")]
    NothingToRollback,
}
