package main

import "fmt"

func clearConsole(n int) {
	for i := 0; i < n; i++ {
		fmt.Print("\033[2K")      // clear the line
		fmt.Printf("\033[%dA", i) // move the cursor up
	}
}
