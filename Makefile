.PHONY: build test clippy fmt fmt-check check doc ci clean
.PHONY: worktree-start worktree-clean worktree-list
.PHONY: team-start team-stop
.PHONY: clab-deploy clab-test clab-destroy clab-e2e
.PHONY: soak-test soak-test-short
.PHONY: rfc-check rfc-registry

# ── Build ──────────────────────────────────────────────

build:
	cargo build --workspace

test:
	cargo test --workspace

clippy:
	cargo clippy --workspace -- -D warnings

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

check:
	cargo check --workspace

doc:
	RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps

ci: check fmt-check clippy test doc
	@echo "All CI checks passed."

clean:
	cargo clean

# ── Worktree ───────────────────────────────────────────

# Usage: make worktree-start NUM=87 DESC=dpdk-base
worktree-start:
	@test -n "$(NUM)" || (echo "ERROR: NUM is required (e.g. make worktree-start NUM=87 DESC=dpdk-base)" && exit 1)
	@test -n "$(DESC)" || (echo "ERROR: DESC is required (e.g. make worktree-start NUM=87 DESC=dpdk-base)" && exit 1)
	git fetch origin
	git worktree add .worktrees/$(NUM)-$(DESC) -b issue/$(NUM)-$(DESC) origin/main

# Usage: make worktree-clean NUM=87 DESC=dpdk-base
worktree-clean:
	@test -n "$(NUM)" || (echo "ERROR: NUM is required" && exit 1)
	@test -n "$(DESC)" || (echo "ERROR: DESC is required" && exit 1)
	git worktree remove .worktrees/$(NUM)-$(DESC)
	-git branch -d issue/$(NUM)-$(DESC)
	git worktree prune

worktree-list:
	git worktree list

# ── Team (tmux) ────────────────────────────────────────

PROJECT_DIR := $(shell pwd)

team-start:
	@if tmux has-session -t ruster-team 2>/dev/null; then \
		echo "Session 'ruster-team' already exists. Attaching..."; \
		tmux attach-session -t ruster-team; \
	else \
		tmux new-session -d -s ruster-team -n main -c $(PROJECT_DIR); \
		tmux split-window -h -t ruster-team -c $(PROJECT_DIR); \
		tmux split-window -v -t ruster-team -c $(PROJECT_DIR); \
		tmux select-pane -t ruster-team:main.0; \
		tmux split-window -v -t ruster-team -c $(PROJECT_DIR); \
		tmux select-layout -t ruster-team tiled; \
		tmux select-pane -t ruster-team:main.0; \
		echo "Session 'ruster-team' created (lead + w1 + w2 + w3)."; \
		tmux attach-session -t ruster-team; \
	fi

team-stop:
	@if tmux has-session -t ruster-team 2>/dev/null; then \
		tmux kill-session -t ruster-team; \
		echo "Session 'ruster-team' killed."; \
	else \
		echo "No session 'ruster-team' found."; \
	fi

# ── Containerlab E2E ──────────────────────────────────

clab-deploy:
	cd tests/containerlab && sudo containerlab deploy --topo topology.yml

clab-test: clab-deploy
	cd tests/containerlab && bash scripts/run-all.sh

clab-destroy:
	cd tests/containerlab && sudo containerlab destroy --topo topology.yml

clab-e2e: clab-test clab-destroy

# ── Soak Tests ────────────────────────────────────────

soak-test:
	cd tests/soak && bash soak-test.sh

soak-test-short:
	cd tests/soak && SOAK_DURATION_MIN=5 bash soak-test.sh

# ── RFC Deviation ────────────────────────────────────────

rfc-check:
	bash scripts/rfc-deviation-lint.sh

rfc-registry:
	bash scripts/rfc-deviation-lint.sh --registry
