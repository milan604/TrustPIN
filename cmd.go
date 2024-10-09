package main

import (
	"fmt"
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
)

func init() {
	addCmd.Flags().IntP("interval", "i", defaultInterval, "Interval in seconds for the TOTP code")
	addCmd.Flags().IntP("digits", "d", defaultDigits, "Number of digits for the TOTP code")
	rootCmd.AddCommand(addCmd)
	rootCmd.AddCommand(showCmd)
}

func addAccount(cmd *cobra.Command, args []string) {
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
