# Ledger Lux

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![GithubActions](https://github.com/luxfi/ledger/actions/workflows/main.yml/badge.svg)](https://github.com/luxfi/ledger/blob/main/.github/workflows/main.yaml)

## Overview

This repository contains the Go client library for interacting with Lux apps on Ledger hardware wallets.

This is a **Go-first** repository with the following structure:

- **Top level**: Go client library (`github.com/luxfi/ledger`)
- **`/rust/`**: Rust implementation and Ledger app source
- **`/go-docs/`**: Additional Go documentation

## Installation

```bash
go get github.com/luxfi/ledger
```

## Usage

```go
import "github.com/luxfi/ledger"

// Example usage
app, err := ledger.FindLedgerLuxUserApp()
if err != nil {
    log.Fatal(err)
}
defer app.Close()

version, err := app.GetVersion()
if err != nil {
    log.Fatal(err)
}

fmt.Printf("App Version: %s\n", version)
```

## Features

- BIP32/BIP44 key derivation
- P2PKH address generation
- Transaction signing
- Message signing
- Multi-signature support

## Testing

Tests require a physical Ledger device with the Lux app installed:

```bash
go test ./...
```

## Development

### Ledger App Development

The Ledger app source code is located in the `/rust/` directory. See `/rust/README.md` for build instructions.

### Go Library Development

The Go client library is at the repository root. Standard Go development practices apply:

```bash
go mod tidy
go test ./...
go build ./...
```

## License

Apache 2.0 - See LICENSE file for details.