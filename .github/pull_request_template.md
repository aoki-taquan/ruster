## Summary

## Scope

- Requirement IDs:
- Explicitly deferred:

## RFC evidence

- RFC and section:
- Deviation ledger update (or `none`):

## Ownership / hot-path review

- [ ] Backend buffers remain borrowed and are commit/recycled exactly once
- [ ] No shared Mutex, packet clone, per-packet String, or dyn PacketIo was added
- [ ] Every drop path before mutation preserves packet bytes

## Validation

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
- [ ] `cargo test --workspace --all-targets --all-features --locked`
- [ ] `cargo test --doc --workspace --all-features --locked`
- [ ] `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked`
- [ ] `cargo check --workspace --all-targets --all-features --locked`
- [ ] `scripts/check-requirements.sh`
- [ ] `scripts/test-check-requirements.sh`
