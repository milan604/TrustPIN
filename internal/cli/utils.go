package cli

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

var ansiPattern = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func clearScreen() {
	fmt.Print("\033[H\033[2J")
}

func terminalWidth() int {
	if value := strings.TrimSpace(os.Getenv("COLUMNS")); value != "" {
		if width, err := strconv.Atoi(value); err == nil && width >= 72 {
			return width
		}
	}

	return 116
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func visibleLen(value string) int {
	return utf8.RuneCountInString(ansiPattern.ReplaceAllString(value, ""))
}

func padRight(value string, width int) string {
	if width <= 0 {
		return ""
	}

	length := visibleLen(value)
	if length >= width {
		return value
	}

	return value + strings.Repeat(" ", width-length)
}

func truncateText(value string, width int) string {
	if width <= 0 {
		return ""
	}

	runes := []rune(strings.TrimSpace(value))
	if len(runes) <= width {
		return string(runes)
	}

	if width <= 3 {
		return string(runes[:width])
	}

	return string(runes[:width-3]) + "..."
}

func alignLine(left, right string, width int) string {
	if width <= 0 {
		return ""
	}

	leftLen := visibleLen(left)
	rightLen := visibleLen(right)
	if leftLen+rightLen >= width {
		return left + " " + right
	}

	return left + strings.Repeat(" ", width-leftLen-rightLen) + right
}

func wrapText(value string, width int) []string {
	if width <= 0 {
		return []string{""}
	}

	words := strings.Fields(value)
	if len(words) == 0 {
		return []string{""}
	}

	lines := make([]string, 0, len(words))
	current := words[0]
	for _, word := range words[1:] {
		next := current + " " + word
		if utf8.RuneCountInString(next) > width {
			lines = append(lines, current)
			current = word
			continue
		}
		current = next
	}
	lines = append(lines, current)

	return lines
}

func pluralize(singular, plural string, count int) string {
	if count == 1 {
		return singular
	}
	return plural
}
