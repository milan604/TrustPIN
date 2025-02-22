package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/fatih/color"
)

type Account struct {
	Name     string
	Secret   string
	Interval int64
	Digits   int
}

func showAllAccounts() {
	accounts, err := loadAccounts()
	if err != nil {
		fmt.Println("Error loading accounts:", err)
		return
	}

	if len(accounts) == 0 {
		fmt.Println("No accounts to show. Please add an account first.")
		return
	}

	longestAccountName := 0
	for _, account := range accounts {
		if len(account.Name) > longestAccountName {
			longestAccountName = len(account.Name)
		}
	}

	nameTabs := "Account "
	nameTabs += strings.Repeat(" ", longestAccountName-8)

	for {
		clearConsole(len(accounts) + 2)

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

		// Print header
		color.Set(color.Bold)     // Set color to bold for the header
		color.Set(color.FgYellow) // Set color to yellow for the header
		fmt.Fprintln(w, nameTabs+"\t\tOTP\t\t\t Expires in (seconds)")
		fmt.Fprintln(w, "___________________________________________________________")
		color.Unset() // Reset color to default

		// Print each account in the table
		for _, account := range accounts {
			otp, timeRemaining := generateTOTP(account.Secret, account.Interval, account.Digits)
			if timeRemaining < 10 {
				color.Set(color.FgRed)
			} else {
				color.Set(color.FgGreen) // Set color for OTP
			}

			accountNameLength := len(account.Name)
			if accountNameLength < longestAccountName {
				account.Name += strings.Repeat(" ", longestAccountName-accountNameLength)
			}

			fmt.Fprintf(w, "%s\t\t%s\t\t%s\n\n", account.Name, otp, fmt.Sprintf("%d", timeRemaining))
		}

		color.Unset() // Reset color after printing the OTP
		// Print the output
		w.Flush()

		time.Sleep(10 * time.Millisecond)
	}
}

func loadAccounts() (accounts []Account, err error) {
	if _, err := os.Stat(accountFile); os.IsNotExist(err) {
		file, err := os.Create(accountFile)
		if err != nil {
			return accounts, err
		}

		encoder := json.NewEncoder(file)
		err = encoder.Encode([]Account{})
		if err != nil {
			return accounts, err
		}

		return accounts, nil
	}

	file, err := os.Open(accountFile)
	if err != nil {
		return
	}

	defer file.Close()

	decoder := json.NewDecoder(file)
	err = decoder.Decode(&accounts)

	return
}

func saveAccounts(accounts []Account) (err error) {
	file, err := os.Create(accountFile)
	if err != nil {
		return
	}

	defer file.Close()

	encoder := json.NewEncoder(file)
	err = encoder.Encode(accounts)

	return
}

func addNewAccount(account, secret string, interval, digits int) {
	fmt.Println("Adding account...")
	accounts, err := loadAccounts()
	if err != nil {
		fmt.Println("Error loading accounts:", err)
		return
	}

	newAccount := Account{
		Name:     account,
		Secret:   secret,
		Interval: int64(interval),
		Digits:   digits,
	}

	accounts = append(accounts, newAccount)

	err = saveAccounts(accounts)
	if err != nil {
		fmt.Println("Error saving accounts:", err)
		return
	}
	fmt.Println(account)
	fmt.Println("Account added successfully!")
}

func deleteAccountByName(account string) {
	accounts, err := loadAccounts()
	if err != nil {
		fmt.Println("Error loading accounts:", err)
		return
	}

	if len(accounts) == 0 {
		fmt.Println("No accounts to delete")
		return
	}

	if account == "" {
		fmt.Println("Please provide an account name to delete or use 'delete all' to delete all accounts")
		return
	}

	if account == "all" {
		err = os.Remove(accountFile)
		if err != nil {
			fmt.Println("Error deleting accounts:", err)
			return
		}

		fmt.Println("All accounts deleted successfully!")
		return
	}

	for i, acc := range accounts {
		if acc.Name == account {
			accounts = append(accounts[:i], accounts[i+1:]...)
			break
		}
	}

	err = saveAccounts(accounts)
	if err != nil {
		fmt.Println("Error saving accounts:", err)
		return
	}

	fmt.Println("Account deleted successfully!")
}
