# TrustPIN

TrustPIN is a local-first TOTP workspace with both a live terminal dashboard and a browser dashboard. It stores accounts in an encrypted local store, supports QR imports, audits account health, and is structured like a conventional Go project so it is easier to build, review, and extend on GitHub.

## Highlights

- Live terminal dashboard with filtering, sorting, compact mode, and focused account inspection.
- Browser dashboard served locally at `trustpin.web.localhost` with JSON APIs for account management and QR imports.
- Web dashboard actions for adding, editing, deleting, and auditing accounts without leaving the app.
- OTP privacy mode that blurs codes by default and reveals them only on card hover, with a one-click toolbar toggle.
- Health audit for invalid secrets, duplicate/shared secrets, risky OTP policies, and naming quality.
- Interactive add flow plus QR import support for standard `otpauth://` and Google Authenticator migration payloads.
- Conventional Go layout with `cmd/` and `internal/` packages instead of a flat repo.
- Automatic first-run migration from legacy plaintext `accounts.json` into encrypted app-data storage.

## Project Layout

```text
.
├── cmd/trustpin/          # binary entrypoint
├── internal/cli/          # Cobra commands + terminal dashboard rendering
├── internal/trustpin/     # core account, OTP, QR import, and audit logic
├── internal/webui/        # local HTTP server + embedded web dashboard
├── Makefile               # common build/run/test targets
└── README.md
```

## Installation

### Using `go install` (recommended)

```bash
go install github.com/milan604/trustPIN/cmd/trustpin@latest
```

### From Release Binary

Download the pre-built binary for your platform from the [Releases](https://github.com/milan604/trustPIN/releases) page:

```bash
# macOS / Linux
chmod +x trustpin
mv trustpin /usr/local/bin/

# Verify
trustpin --help
```

### From Source

Requires **Go 1.25+**.

Build the CLI:

```bash
make build
```

Run the terminal dashboard:

```bash
make run
```

Run tests:

```bash
make test
```

Launch the browser dashboard:

```bash
make serve
```

You can also use plain Go commands:

```bash
go run ./cmd/trustpin
go build -o trustpin ./cmd/trustpin
go test ./...
```

## Usage

Open the live dashboard:

```bash
trustpin
```

Render a one-shot dashboard snapshot:

```bash
trustpin show --once
```

Search or sort the dashboard:

```bash
trustpin show github --sort name
trustpin show --issuer "AWS SSO" --compact
```

Inspect a single account:

```bash
trustpin inspect "AWS SSO:prod"
trustpin inspect GitHub --once
```

Run an account audit:

```bash
trustpin health
```

Migrate a legacy plaintext store manually:

```bash
trustpin migrate
trustpin migrate /path/to/accounts.json
trustpin migrate /path/to/accounts.json --keep-source
```

Start the web dashboard:

```bash
trustpin serve
trustpin serve --port 8090
```

By default TrustPIN binds to `127.0.0.1` and prints a package-friendly local URL such as `http://trustpin.web.localhost:8086`.
In the web dashboard, use the pencil icon on any account card to edit its name, secret, interval, or digit policy. Leaving the secret blank during edit keeps the current secret unchanged.
The toolbar privacy toggle controls whether OTP codes stay blurred by default or remain fully visible.

Add an account directly:

```bash
trustpin add GitHub JBSWY3DPEHPK3PXP
```

Add an account with a custom interval or digit count:

```bash
trustpin add Example ABCDEF123456 -i 60 -d 8
```

Use the interactive add flow:

```bash
trustpin add
trustpin add GitHub
```

Import accounts from a QR image:

```bash
trustpin add --qr-file ./provisioning-qr.png
```

Supported QR payloads:

- `otpauth://totp/Issuer:Account?secret=BASE32&period=30&digits=6`
- `otpauth-migration://offline?data=<base64 protobuf payload>`

Delete accounts:

```bash
trustpin delete GitHub
trustpin delete account1 account2
trustpin delete
trustpin delete --force
```

Use a custom encrypted store path:

```bash
trustpin --accounts-file ./data/accounts.enc
```

## Storage

TrustPIN stores accounts in an encrypted store by default.

- Default location:
  macOS: `~/Library/Application Support/TrustPIN/accounts.enc`
  Linux: `${XDG_CONFIG_HOME:-~/.config}/TrustPIN/accounts.enc`
  Windows: `%AppData%/TrustPIN/accounts.enc`
- A per-user encryption key is created automatically alongside the store on first run.
- If a legacy plaintext `accounts.json` is found in the current working directory, TrustPIN migrates it automatically into encrypted storage.
- If your old plaintext file lives somewhere else, run `trustpin migrate /path/to/accounts.json`.
- Secrets may be Base32 or Base64.
- Legacy plaintext files are still ignored by Git to avoid accidental commits during migration.

## Maintainer Notes

- `internal/trustpin` is the shared core used by both the CLI and web server.
- `internal/cli` owns terminal rendering only.
- `internal/webui` owns HTTP handlers and the embedded frontend only.
- The repo ships a `Makefile` so common tasks stay consistent across contributors.

## License

MIT
