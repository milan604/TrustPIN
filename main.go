package main

import (
	"fmt"
	"os"
)

const (
	accountFile      = "accounts.json"
	defaultInterval  = 30
	defaultDigits    = 6
	usageMessage     = "Usage: trustPIN [add <account> <secret> <interval> <digits>] | [show]"
	intervalErrorMsg = "Interval must be a positive integer"
	digitsErrorMsg   = "Digits must be between 1 and 10"
	secretPrompt     = "Please enter a secure secret key for your account:"
	accountPrompt    = "Please enter a unique account name:"
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
