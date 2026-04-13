package main

import (
	"fmt"
	"os"

	"github.com/milan604/trustPIN/internal/cli"
	"github.com/milan604/trustPIN/internal/trustpin"
)

func main() {
	rootCmd := cli.NewRootCmd(trustpin.NewService(""))
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
