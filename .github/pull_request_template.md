## 何を変えたか

## なぜ

## 確認

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
- [ ] `cargo test --workspace --all-targets --all-features --locked`
- [ ] `cargo test --doc --workspace --all-features --locked`
- [ ] `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked`
- [ ] `cargo check --workspace --all-targets --all-features --locked`

## 転送の処理経路（触ったときだけ）

- [ ] パケットのbufferは借りるだけで、送信か返却で必ず一度だけ終える
- [ ] 共有`Mutex`、パケットのclone、パケットごとの`String`、`dyn PacketIo`を入れていない
