# Tornado-opt-backend

## Generate Solidity Verifier

```bash
cargo test -r test_save_solidity_verifier -- --nocapture --ignored
```

## Run CLI

```bash
cargo run -- --help
```

### Deposit

```bash
cargo run -- deposit --private-key <your_private_key>
```

### Withdrawal

```bash
cargo run -- withdrawal --private-key <your_private_key> --nullifier <your_nullifier> --secret <your_secret>
```

### Save Checkpoint on Chain

```bash
cargo run -- checkpoint --private-key <your_private_key>
```
