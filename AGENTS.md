# Repository Guidelines

## Project Structure & Module Organization
- `src/`: Rust sources. Library entry at `src/lib.rs` (exports `merkle_tree`); binary entry at `src/main.rs`.
- `src/merkle_tree.rs`: Poseidon-based Merkle tree, with unit tests in-module.
- `abi/`: Contract artifacts (e.g., `abi/TornadoOptV1.json`). Keep in sync with the deployed contract.
- `TornadoOptV1.sol`: Reference Solidity contract. Not built here; used for ABI alignment.
- `Cargo.toml`: Workspace metadata and dependencies (arkworks, alloy, folding-schemes).

## Build, Test, and Development Commands
- Build: `cargo build` — compiles the library and binary.
- Run: `cargo run` — runs the demo binary (currently prints a placeholder).
- Test: `cargo test` — runs Rust unit tests (see `#[cfg(test)]` in `merkle_tree.rs`).
- Lint: `cargo clippy --all-targets -- -D warnings` — static checks; fix before pushing.
- Format: `cargo fmt --all` — apply Rust style formatting.

## Coding Style & Naming Conventions
- Use rustfmt defaults; run formatting and clippy locally.
- Modules: snake_case files and module names (e.g., `merkle_tree`); public types use UpperCamelCase; functions/variables use snake_case.
- Error handling: prefer `anyhow::Result<T>` for app-level flows; avoid `unwrap()` outside tests/examples.
- Constants and sizes: prefer explicit types for field elements and indices.

## Testing Guidelines
- Framework: Rust `#[test]` unit tests; place quick tests in-module. For integration tests, add files under `tests/` using `cargo test`.
- Naming: `test_<behavior>()` and clear arrange/act/assert blocks.
- Coverage: no strict threshold; add tests for new logic (Merkle paths, edge cases, failure checks).

## Commit & Pull Request Guidelines
- Commits: short, imperative subject in lowercase; optional scope (e.g., `impl: merkle tree`). Group related changes.
- PRs: include summary, rationale, and links to issues. Show relevant commands/output (e.g., `cargo test`) and describe any ABI or contract changes.
- Checks: ensure `cargo fmt`, `cargo clippy`, and `cargo test` pass.

## Security & ABI Notes
- ABI changes: update `abi/TornadoOptV1.json` together with contract changes and note network/deployment details.
- Determinism: when hashing, avoid nondeterministic randomness paths in production code.
