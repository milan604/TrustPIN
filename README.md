able to change pin rotate interval and change number of pin digits

# TrustPIN

TrustPIN is a small command-line tool for managing Time-based One-Time Passwords (TOTP). It stores accounts in a local JSON file (`accounts.json`) and can generate current OTPs for each account.

## Features

- Add accounts by specifying account name and secret.
- Import accounts from a provisioning QR code image (supports both raw `otpauth://` URIs and Google Authenticator migration QR `otpauth-migration://offline?data=...`).
- Avoid duplicate entries: adding an account will replace an existing account when the account name or the secret matches.
- Show all accounts with color-coded OTPs and time-to-expiry.
- Delete single accounts or delete all accounts (with confirmation).

## Requirements

- Go 1.16+

All Go module dependencies are managed in `go.mod`; `go build` or `go install` will fetch them automatically.

## Install

Build and install locally:

```bash
cd /path/to/TrustPIN
go install ./...
```

Or build a binary:

```bash
go build -o trustPIN
```

## Usage

Add an account by name + secret:

```bash
trustPIN add MyAccount MYSECRETBASE32
```

You can set the TOTP interval (seconds) and the number of digits:

```bash
trustPIN add GitHub ABCDEF123456 -i 60 -d 4
```

Import from a QR image (common for provisioning QR codes):

```bash
trustPIN add --qr-file path/to/provisioning-qr.png
```

Supported QR payloads:
- otpauth://totp/Issuer:Account?secret=BASE32&period=30&digits=6
- otpauth-migration://offline?data=<base64 protobuf payload> (Google Authenticator export/migration)

When importing a migration QR that contains multiple accounts, TrustPIN will add all accounts found. If an account with the same name or secret already exists, it will be replaced.

Show current OTPs for all accounts:

```bash
trustPIN show
```

Delete accounts:

- Delete specific accounts by name:

```bash
trustPIN delete account1 account2
```

- Delete all accounts:

```bash
trustPIN delete
```

Running `trustPIN delete` with no arguments will prompt for confirmation before removing all accounts. You can also run `trustPIN delete all` which will delete all accounts immediately.

## Storage

Accounts are stored in the working directory in a file named `accounts.json`. Back up this file if you need to migrate or preserve accounts.

## Notes

- Secrets may be Base32 or Base64; the tool will attempt to decode either when generating OTPs.
- When importing migration payloads, the migration protobuf encodes some fields as enums — the tool maps common enum values to actual digit lengths (e.g., enum values commonly used for 6/8 digits).
- If you prefer interactive confirmation when importing multiple accounts, or a different deduplication policy (e.g. prefer matching by secret only), I can add those behaviors.

## License

MIT

