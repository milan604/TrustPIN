package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var (
	rootCmd = &cobra.Command{
		Use:   "trustPIN",
		Short: "Manage your TOTP accounts",
		Long:  "A command line application to manage your TOTP accounts and generate one-time passwords",
	}

	addCmd = &cobra.Command{
		Use:   "add [account] [secret] [interval] [digits]",
		Short: "Add a new TOTP account",
		Long:  "Add a new TOTP account with the specified account name, secret, interval, and digits",
		Run:   addAccount,
	}

	showCmd = &cobra.Command{
		Use:   "show",
		Short: "Show all or a specific TOTP account",
		Long:  "Display all or a specific TOTP account and its current OTP.",
		Run:   showAccounts,
	}

	deleteCmd = &cobra.Command{
		Use:   "delete [account]",
		Short: "Delete one/many TOTP account",
		Long:  "Delete one or many TOTP account by providing the account name",
		Run:   deleteAccounts,
	}
)

func init() {
	addCmd.Flags().IntP("interval", "i", defaultInterval, "Interval in seconds for the TOTP code")
	addCmd.Flags().IntP("digits", "d", defaultDigits, "Number of digits for the TOTP code")
	addCmd.Flags().StringP("qr-file", "q", "", "Path to a QR image file containing an otpauth:// URI to add the account from")
	rootCmd.AddCommand(addCmd)
	rootCmd.AddCommand(showCmd)
	rootCmd.AddCommand(deleteCmd)
}

func addAccount(cmd *cobra.Command, args []string) {
	qrFile, _ := cmd.Flags().GetString("qr-file")

	if qrFile != "" {
		uri, err := readQRFromFile(qrFile)
		if err != nil {
			fmt.Println("Error reading QR file:", err)
			return
		}

		accounts, err := parseQRPayload(uri)
		if err != nil {
			fmt.Println("Error parsing QR payload:", err)
			return
		}

		for _, a := range accounts {
			if err := validateDigits(a.Digits); err != nil {
				fmt.Printf("Skipping account %s: %v\n", a.Name, err)
				continue
			}
			addNewAccount(a.Name, a.Secret, int(a.Interval), a.Digits)
		}

		return
	}

	if len(args) < 2 {
		fmt.Println("Error: account and secret are required unless --qr-file is provided")
		return
	}

	account := args[0]
	secret := args[1]

	if err := validateInput(account, secret); err != nil {
		fmt.Println("Error:", err)
		return
	}

	interval, _ := cmd.Flags().GetInt("interval")
	digits, _ := cmd.Flags().GetInt("digits")

	if err := validateDigits(digits); err != nil {
		fmt.Println("Error:", err)
		return
	}

	addNewAccount(account, secret, interval, digits)
}

func showAccounts(cmd *cobra.Command, args []string) {
	showAllAccounts()
}

func deleteAccounts(cmd *cobra.Command, args []string) {
	if len(args) == 0 {
		// No args: ask for confirmation to delete all accounts
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Are you sure you want to delete ALL accounts? (y/N): ")
		resp, _ := reader.ReadString('\n')
		resp = strings.TrimSpace(strings.ToLower(resp))
		if resp == "y" || resp == "yes" {
			deleteAccountByName("all")
		} else {
			fmt.Println("Aborted: no accounts were deleted.")
		}
		return
	}

	for _, account := range args {
		deleteAccountByName(account)
	}
}

func validateInput(account, secret string) error {
	if strings.TrimSpace(account) == "" {
		return fmt.Errorf("account name cannot be empty")
	}

	if strings.TrimSpace(secret) == "" {
		return fmt.Errorf("secret cannot be empty")
	}

	return nil
}

func validateDigits(digits int) error {
	if digits < 1 || digits > 10 {
		return fmt.Errorf("digits must be between 1 and 10")
	}
	return nil
}
