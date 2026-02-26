#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    #[error("validation failed: {0}")]
    Validation(String),

    #[error("nothing to commit: no running configuration")]
    NothingToCommit,

    #[error("transaction conflict: another transaction is already in progress")]
    TransactionConflict,

    #[error("no committed configuration: commit a running config first")]
    NoCommittedConfig,

    #[error("transaction already in progress")]
    TransactionInProgress,

    #[error("no running configuration")]
    NoRunningConfig,

    #[error("no active transaction")]
    NoTransaction,

    #[error("invalid transaction state: expected {expected}, got {actual}")]
    InvalidTransactionState { expected: String, actual: String },
}
