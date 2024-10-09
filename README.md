# TrustPIN

TrustPIN is a command-line tool for managing time-based one-time passwords (TOTP) for multiple accounts. It allows you to securely store account information and generate OTPs that expire at specified intervals. 

## Features

- Add new accounts with secrets, intervals, and digit lengths.
- Display current OTPs for all stored accounts with expiration times.
- Color-coded output for improved readability.
- Tabular format for clear presentation of account information.

## Requirements

- Go (version 1.16 or higher)
- Dependencies: [Cobra](https://github.com/spf13/cobra), [fatih/color](https://github.com/fatih/color)

## Installation

To install TrustPIN, run the following command:

```bash
go install github.com/yourusername/trustPIN@latest

