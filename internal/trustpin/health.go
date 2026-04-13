package trustpin

import (
	"fmt"
	"sort"
	"strings"
)

type HealthLevel string

const (
	HealthLevelCritical HealthLevel = "critical"
	HealthLevelWarning  HealthLevel = "warning"
	HealthLevelInfo     HealthLevel = "info"
)

type HealthItem struct {
	Level   HealthLevel `json:"level"`
	Title   string      `json:"title"`
	Detail  string      `json:"detail"`
	Account string      `json:"account,omitempty"`
}

type HealthSummary struct {
	Critical int `json:"critical"`
	Warning  int `json:"warning"`
	Info     int `json:"info"`
}

type HealthReport struct {
	Items   []HealthItem  `json:"items"`
	Summary HealthSummary `json:"summary"`
	Total   int           `json:"total"`
}

func AnalyzeAccounts(accounts []Account) []HealthItem {
	items := make([]HealthItem, 0)
	if len(accounts) == 0 {
		return items
	}

	nameGroups := make(map[string][]string)
	secretGroups := make(map[string][]string)
	missingIssuer := make([]string, 0)

	for _, account := range accounts {
		account = sanitizeAccount(account)
		nameKey := normalizeAccountName(account.Name)
		nameGroups[nameKey] = append(nameGroups[nameKey], account.Name)

		secretKey := normalizeSecret(account.Secret)
		if secretKey != "" {
			secretGroups[secretKey] = append(secretGroups[secretKey], account.Name)
		}

		if _, _, hasIssuer := SplitAccountName(account.Name); !hasIssuer {
			missingIssuer = append(missingIssuer, account.Name)
		}

		if _, _, err := GenerateTOTP(account.Secret, account.Interval, account.Digits); err != nil {
			items = append(items, HealthItem{
				Level:   HealthLevelCritical,
				Title:   "Invalid secret",
				Detail:  fmt.Sprintf("%s cannot generate OTP codes because the secret is not valid base32 or base64.", account.Name),
				Account: account.Name,
			})
		}

		if account.Type == TypeHOTP {
			items = append(items, HealthItem{
				Level:   HealthLevelInfo,
				Title:   "Counter-based OTP",
				Detail:  fmt.Sprintf("%s uses HOTP (counter %d). Counter desync may require re-enrollment.", account.Name, account.Counter),
				Account: account.Name,
			})
		}

		if account.Type == TypeSteam {
			items = append(items, HealthItem{
				Level:   HealthLevelInfo,
				Title:   "Steam Guard",
				Detail:  fmt.Sprintf("%s uses Steam Guard authentication with 5-character alphanumeric codes.", account.Name),
				Account: account.Name,
			})
		}

		if account.Type == TypeTOTP && (account.Interval != DefaultInterval || account.Digits != DefaultDigits) {
			level := HealthLevelInfo
			if account.Interval < 20 || account.Digits < 6 {
				level = HealthLevelWarning
			}

			items = append(items, HealthItem{
				Level:   level,
				Title:   "Custom policy",
				Detail:  fmt.Sprintf("%s uses %d digits and a %ds rotation window.", account.Name, account.Digits, account.Interval),
				Account: account.Name,
			})
		}
	}

	for _, names := range nameGroups {
		if len(names) <= 1 {
			continue
		}
		sort.Strings(names)
		items = append(items, HealthItem{
			Level:  HealthLevelWarning,
			Title:  "Duplicate names",
			Detail: fmt.Sprintf("Multiple entries share the same account name: %s.", strings.Join(names, ", ")),
		})
	}

	for _, names := range secretGroups {
		if len(names) <= 1 {
			continue
		}
		sort.Strings(names)
		items = append(items, HealthItem{
			Level:  HealthLevelWarning,
			Title:  "Shared secret",
			Detail: fmt.Sprintf("These accounts appear to reuse the same secret: %s.", strings.Join(names, ", ")),
		})
	}

	if len(missingIssuer) > 0 {
		sort.Strings(missingIssuer)
		items = append(items, HealthItem{
			Level:  HealthLevelInfo,
			Title:  "Ungrouped names",
			Detail: fmt.Sprintf("%d %s do not include an issuer prefix. Naming them as Issuer:Label improves dashboard grouping.", len(missingIssuer), pluralize("account", "accounts", len(missingIssuer))),
		})
	}

	sort.SliceStable(items, func(i, j int) bool {
		return healthPriority(items[i].Level) < healthPriority(items[j].Level)
	})

	return items
}

func SummarizeHealth(items []HealthItem) HealthSummary {
	summary := HealthSummary{}
	for _, item := range items {
		switch item.Level {
		case HealthLevelCritical:
			summary.Critical++
		case HealthLevelWarning:
			summary.Warning++
		case HealthLevelInfo:
			summary.Info++
		}
	}
	return summary
}

func (s Service) HealthReport() (HealthReport, error) {
	accounts, err := s.LoadAccounts()
	if err != nil {
		return HealthReport{}, err
	}

	items := AnalyzeAccounts(accounts)
	return HealthReport{
		Items:   items,
		Summary: SummarizeHealth(items),
		Total:   len(accounts),
	}, nil
}

func healthPriority(level HealthLevel) int {
	switch level {
	case HealthLevelCritical:
		return 0
	case HealthLevelWarning:
		return 1
	default:
		return 2
	}
}

func pluralize(singular, plural string, count int) string {
	if count == 1 {
		return singular
	}
	return plural
}
