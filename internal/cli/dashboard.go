package cli

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/milan604/trustPIN/internal/trustpin"
)

const (
	toneAccent  = "accent"
	toneSuccess = "success"
	toneWarning = "warning"
	toneDanger  = "danger"
	toneMuted   = "muted"
)

var (
	brandText   = color.New(color.Bold, color.FgHiCyan).SprintFunc()
	headingText = color.New(color.Bold, color.FgWhite).SprintFunc()
	accentText  = color.New(color.Bold, color.FgHiBlue).SprintFunc()
	successText = color.New(color.Bold, color.FgHiGreen).SprintFunc()
	warningText = color.New(color.Bold, color.FgHiYellow).SprintFunc()
	dangerText  = color.New(color.Bold, color.FgHiRed).SprintFunc()
	mutedText   = color.New(color.FgHiBlack).SprintFunc()
	borderText  = color.New(color.FgHiBlack).SprintFunc()
)

type showOptions struct {
	Search  string
	Issuer  string
	SortBy  string
	Watch   bool
	Compact bool
}

type accountViewModel struct {
	Account         trustpin.Account
	FullName        string
	DisplayName     string
	Issuer          string
	Label           string
	FormattedOTP    string
	TimeRemaining   int64
	StatusLabel     string
	Tone            string
	ErrorText       string
	SecretPreview   string
	PolicyLabel     string
	ProgressBar     string
	ProgressPercent int
}

type dashboardStats struct {
	Total          int
	Visible        int
	Issuers        int
	ExpiringSoon   int
	CustomPolicies int
	Audit          trustpin.HealthSummary
}

func showDashboard(service trustpin.Service, opts showOptions) error {
	sortBy, err := normalizeSort(opts.SortBy)
	if err != nil {
		return err
	}
	opts.SortBy = sortBy

	if !opts.Watch {
		return renderDashboardFrame(service, opts)
	}

	for {
		if err := renderDashboardFrame(service, opts); err != nil {
			return err
		}
		time.Sleep(1 * time.Second)
	}
}

func renderDashboardFrame(service trustpin.Service, opts showOptions) error {
	accounts, err := service.LoadAccounts()
	if err != nil {
		return err
	}

	viewModels, stats := buildDashboardView(accounts, opts)
	output := renderDashboard(viewModels, stats, opts, service.StorePath)
	if opts.Watch {
		clearScreen()
	}

	fmt.Print(output)
	return nil
}

func inspectAccount(service trustpin.Service, query string, watch bool) error {
	query = strings.TrimSpace(query)
	if query == "" {
		return fmt.Errorf("account query cannot be empty")
	}

	if !watch {
		return renderInspectFrame(service, query, false)
	}

	for {
		if err := renderInspectFrame(service, query, true); err != nil {
			return err
		}
		time.Sleep(1 * time.Second)
	}
}

func renderInspectFrame(service trustpin.Service, query string, clear bool) error {
	accounts, err := service.LoadAccounts()
	if err != nil {
		return err
	}

	account, suggestions, found, ambiguous := resolveInspectAccount(accounts, query)
	if clear {
		clearScreen()
	}
	if !found || ambiguous {
		fmt.Print(renderInspectFallback(query, suggestions, ambiguous))
		return nil
	}

	view := buildAccountViewModel(account)
	fmt.Print(renderInspectView(view, clear))
	return nil
}

func showHealthReport(service trustpin.Service) error {
	report, err := service.HealthReport()
	if err != nil {
		return err
	}

	fmt.Print(renderHealthReport(report))
	return nil
}

func buildDashboardView(accounts []trustpin.Account, opts showOptions) ([]accountViewModel, dashboardStats) {
	views := make([]accountViewModel, 0, len(accounts))
	issuerGroups := make(map[string]struct{})
	customPolicies := 0
	expiringSoon := 0

	for _, account := range accounts {
		account = sanitizeAccount(account)
		issuer, _, hasIssuer := trustpin.SplitAccountName(account.Name)
		group := "ungrouped"
		if hasIssuer {
			group = strings.ToLower(issuer)
		}
		issuerGroups[group] = struct{}{}

		if account.Interval != trustpin.DefaultInterval || account.Digits != trustpin.DefaultDigits {
			customPolicies++
		}

		if !matchesAccountFilters(account, opts) {
			continue
		}

		view := buildAccountViewModel(account)
		if view.ErrorText == "" && view.TimeRemaining <= 5 {
			expiringSoon++
		}
		views = append(views, view)
	}

	sortViewModels(views, opts.SortBy)
	audit := trustpin.SummarizeHealth(trustpin.AnalyzeAccounts(accounts))

	return views, dashboardStats{
		Total:          len(accounts),
		Visible:        len(views),
		Issuers:        len(issuerGroups),
		ExpiringSoon:   expiringSoon,
		CustomPolicies: customPolicies,
		Audit:          audit,
	}
}

func buildAccountViewModel(account trustpin.Account) accountViewModel {
	snapshot := trustpin.BuildAccountSnapshot(account)
	return accountViewModel{
		Account:         snapshot.Account,
		FullName:        snapshot.Name,
		DisplayName:     snapshot.DisplayName,
		Issuer:          snapshot.Issuer,
		Label:           snapshot.Label,
		FormattedOTP:    snapshot.FormattedOTP,
		TimeRemaining:   snapshot.TimeRemaining,
		StatusLabel:     snapshot.StatusLabel,
		Tone:            snapshot.Tone,
		ErrorText:       snapshot.ErrorText,
		SecretPreview:   snapshot.SecretPreview,
		PolicyLabel:     snapshot.PolicyLabel,
		ProgressBar:     progressBar(snapshot.ProgressPercent, 18),
		ProgressPercent: snapshot.ProgressPercent,
	}
}

func matchesAccountFilters(account trustpin.Account, opts showOptions) bool {
	issuer, label, _ := trustpin.SplitAccountName(account.Name)
	haystack := strings.ToLower(strings.Join([]string{account.Name, issuer, label}, " "))

	if opts.Search != "" && !containsAllTerms(haystack, strings.Fields(strings.ToLower(opts.Search))) {
		return false
	}
	if opts.Issuer != "" && !strings.Contains(strings.ToLower(issuer), strings.ToLower(opts.Issuer)) {
		return false
	}

	return true
}

func containsAllTerms(haystack string, terms []string) bool {
	for _, term := range terms {
		if !strings.Contains(haystack, term) {
			return false
		}
	}
	return true
}

func normalizeSort(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "expiry":
		return "expiry", nil
	case "name":
		return "name", nil
	case "issuer":
		return "issuer", nil
	case "digits":
		return "digits", nil
	default:
		return "", fmt.Errorf("unsupported sort %q (use expiry, name, issuer, or digits)", value)
	}
}

func sortViewModels(accounts []accountViewModel, sortBy string) {
	sort.SliceStable(accounts, func(i, j int) bool {
		left := accounts[i]
		right := accounts[j]

		switch sortBy {
		case "name":
			return normalizeAccountName(left.FullName) < normalizeAccountName(right.FullName)
		case "issuer":
			if strings.ToLower(left.Issuer) == strings.ToLower(right.Issuer) {
				return normalizeAccountName(left.FullName) < normalizeAccountName(right.FullName)
			}
			return strings.ToLower(left.Issuer) < strings.ToLower(right.Issuer)
		case "digits":
			if left.Account.Digits == right.Account.Digits {
				return normalizeAccountName(left.FullName) < normalizeAccountName(right.FullName)
			}
			return left.Account.Digits < right.Account.Digits
		default:
			if left.TimeRemaining == right.TimeRemaining {
				return normalizeAccountName(left.FullName) < normalizeAccountName(right.FullName)
			}
			return left.TimeRemaining < right.TimeRemaining
		}
	})
}

func renderDashboard(accounts []accountViewModel, stats dashboardStats, opts showOptions, accountFile string) string {
	width := terminalWidth()
	lines := make([]string, 0, 64)

	headerLines := []string{
		brandText("TRUSTPIN") + " " + headingText("LIVE OTP WORKSPACE"),
		mutedText("Readable one-time codes, import-friendly workflows, and account health signals in one terminal view."),
		"",
		strings.Join([]string{
			renderMetricBadge(toneAccent, map[bool]string{true: "LIVE", false: "SNAPSHOT"}[opts.Watch]),
			renderMetricBadge(toneSuccess, fmt.Sprintf("%d visible", stats.Visible)),
			renderMetricBadge(toneAccent, fmt.Sprintf("%d total", stats.Total)),
			renderMetricBadge(toneWarning, fmt.Sprintf("%d expiring", stats.ExpiringSoon)),
			renderMetricBadge(toneAccent, fmt.Sprintf("%d groups", stats.Issuers)),
			renderMetricBadge(toneAccent, fmt.Sprintf("%d custom", stats.CustomPolicies)),
			renderMetricBadge(toneDanger, fmt.Sprintf("%d critical", stats.Audit.Critical)),
		}, " "),
	}

	filterParts := make([]string, 0, 4)
	if opts.Search != "" {
		filterParts = append(filterParts, "search "+opts.Search)
	}
	if opts.Issuer != "" {
		filterParts = append(filterParts, "issuer "+opts.Issuer)
	}
	filterParts = append(filterParts, "sort "+opts.SortBy)
	filterParts = append(filterParts, map[bool]string{true: "layout compact", false: "layout cards"}[opts.Compact])
	headerLines = append(headerLines, mutedText(strings.Join(filterParts, " | ")))
	headerLines = append(headerLines, mutedText("Storage "+accountFile+" | "+map[bool]string{true: "Ctrl+C exits watch mode", false: "Use --watch to keep the dashboard live"}[opts.Watch]+" | trustpin inspect <account> opens a focused view"))

	lines = append(lines, renderPanel("Command center", headerLines, min(width, 116))...)
	lines = append(lines, "")

	if stats.Total == 0 {
		lines = append(lines, renderPanel("Get started", []string{
			headingText("No accounts stored yet."),
			"Add one with `trustpin add GitHub ABCDEF123456` or import from a screenshot with `trustpin add --qr-file ./IMG_7222.PNG`.",
			"Run `trustpin health` any time to audit secrets, naming, and custom rotation policies.",
		}, min(width, 108))...)
		return strings.Join(lines, "\n") + "\n"
	}

	if stats.Visible == 0 {
		lines = append(lines, renderPanel("No matching accounts", []string{
			headingText("Current filters returned no accounts."),
			"Try `trustpin show --sort name`, remove the issuer filter, or search with a shorter term.",
		}, min(width, 100))...)
		return strings.Join(lines, "\n") + "\n"
	}

	if opts.Compact || width < 96 {
		lines = append(lines, renderCompactList(accounts, min(width, 116))...)
	} else {
		lines = append(lines, renderCardGrid(accounts, min(width, 116))...)
	}

	lines = append(lines, "")
	lines = append(lines, mutedText("Commands: trustpin add | trustpin add --qr-file <image> | trustpin show --once | trustpin inspect <account> | trustpin health"))

	return strings.Join(lines, "\n") + "\n"
}

func renderHealthReport(report trustpin.HealthReport) string {
	width := min(terminalWidth(), 100)
	lines := []string{
		brandText("TRUSTPIN HEALTH"),
		mutedText("Quality and security review for your local TOTP workspace."),
		"",
		strings.Join([]string{
			renderHealthBadge(trustpin.HealthLevelCritical, fmt.Sprintf("%d critical", report.Summary.Critical)),
			renderHealthBadge(trustpin.HealthLevelWarning, fmt.Sprintf("%d warnings", report.Summary.Warning)),
			renderHealthBadge(trustpin.HealthLevelInfo, fmt.Sprintf("%d info", report.Summary.Info)),
			renderHealthBadge(trustpin.HealthLevelInfo, fmt.Sprintf("%d total %s", report.Total, pluralize("account", "accounts", report.Total))),
		}, " "),
	}

	if report.Total == 0 {
		lines = append(lines,
			"",
			mutedText("No accounts stored yet."),
			"Add an account with `trustpin add` or import from a screenshot with `trustpin add --qr-file ./image.png`.",
		)
		return strings.Join(renderPanel("Workspace status", lines, width), "\n") + "\n"
	}

	if len(report.Items) == 0 {
		lines = append(lines,
			"",
			successText("No issues detected."),
			"Your accounts are decodable, consistently configured, and ready for the live dashboard.",
		)
		return strings.Join(renderPanel("Workspace status", lines, width), "\n") + "\n"
	}

	for _, item := range report.Items {
		lines = append(lines, "")
		lines = append(lines, styleHealthHeading(item.Level, item.Title))
		lines = append(lines, wrapText(item.Detail, width-4)...)
	}

	return strings.Join(renderPanel("Workspace status", lines, width), "\n") + "\n"
}

func renderCompactList(accounts []accountViewModel, width int) []string {
	inner := width - 4
	accountWidth := min(30, inner/2)
	if accountWidth < 18 {
		accountWidth = 18
	}

	lines := []string{
		alignLine(mutedText(padRight("ACCOUNT", accountWidth)+" OTP        LEFT  POLICY           STATE"), mutedText(""), inner),
		mutedText(strings.Repeat("-", inner)),
	}

	for _, account := range accounts {
		left := truncateText(account.FullName, accountWidth)
		otp := truncateText(account.FormattedOTP, 10)
		policy := truncateText(account.PolicyLabel, 15)
		leftSeconds := "--"
		if account.ErrorText == "" {
			leftSeconds = fmt.Sprintf("%2ds", account.TimeRemaining)
		}
		line := fmt.Sprintf("%s %-10s %4s  %-15s %s",
			padRight(left, accountWidth),
			otp,
			leftSeconds,
			policy,
			account.StatusLabel,
		)
		lines = append(lines, styleTone(account.Tone, truncateText(line, inner)))
	}

	return renderPanel("Accounts", lines, width)
}

func renderCardGrid(accounts []accountViewModel, width int) []string {
	columns := 1
	cardWidth := width
	if width >= 104 {
		columns = 2
		cardWidth = (width - 2) / 2
	}

	cards := make([][]string, 0, len(accounts))
	for _, account := range accounts {
		cards = append(cards, renderAccountCard(account, cardWidth))
	}

	lines := make([]string, 0, len(cards)*10)
	for i := 0; i < len(cards); i += columns {
		rowCards := cards[i:min(i+columns, len(cards))]
		rowHeight := 0
		for _, card := range rowCards {
			rowHeight = max(rowHeight, len(card))
		}

		for lineIndex := 0; lineIndex < rowHeight; lineIndex++ {
			parts := make([]string, 0, len(rowCards))
			for _, card := range rowCards {
				if lineIndex < len(card) {
					parts = append(parts, card[lineIndex])
					continue
				}
				parts = append(parts, strings.Repeat(" ", cardWidth))
			}
			lines = append(lines, strings.Join(parts, "  "))
		}
		lines = append(lines, "")
	}

	return lines
}

func renderAccountCard(account accountViewModel, width int) []string {
	inner := width - 4
	timerText := "--"
	if account.ErrorText == "" {
		timerText = fmt.Sprintf("%2ds", account.TimeRemaining)
	}

	lines := []string{
		alignLine(headingText(truncateText(account.DisplayName, inner-10)), styleTone(account.Tone, timerText), inner),
		mutedText(truncateText("issuer "+account.Issuer+" | "+account.PolicyLabel, inner)),
		"",
		styleTone(account.Tone, account.FormattedOTP),
		alignLine(mutedText("status "+strings.ToLower(account.StatusLabel)), mutedText(account.FullName), inner),
		alignLine(mutedText("cycle  "+account.ProgressBar), mutedText(fmt.Sprintf("%d%%", account.ProgressPercent)), inner),
		styleTone(map[bool]string{true: toneDanger, false: toneMuted}[account.ErrorText != ""], truncateText(account.noteLine(), inner)),
	}

	return renderPanel("", lines, width)
}

func (account accountViewModel) noteLine() string {
	if account.ErrorText != "" {
		return account.ErrorText
	}
	return "secret " + account.SecretPreview
}

func renderInspectView(account accountViewModel, live bool) string {
	width := min(terminalWidth(), 96)
	modeLabel := "Focused snapshot for a single account."
	if live {
		modeLabel = "Focused live view for a single account."
	}

	timer := "--"
	if account.ErrorText == "" {
		timer = fmt.Sprintf("%2ds left", account.TimeRemaining)
	}

	lines := []string{
		brandText("TRUSTPIN") + " " + headingText("ACCOUNT INSPECTOR"),
		mutedText(modeLabel),
		"",
		alignLine(headingText(account.FullName), styleTone(account.Tone, timer), width-4),
		mutedText("issuer " + account.Issuer + " | " + account.PolicyLabel),
		"",
		styleTone(account.Tone, account.FormattedOTP),
		mutedText("status " + strings.ToLower(account.StatusLabel)),
		mutedText("cycle  " + account.ProgressBar + fmt.Sprintf("  %d%%", account.ProgressPercent)),
		mutedText("secret " + account.SecretPreview),
	}

	if account.ErrorText != "" {
		lines = append(lines, dangerText(account.ErrorText))
	}
	lines = append(lines, "")
	lines = append(lines, mutedText("Use `trustpin show` to return to the full dashboard."))

	return strings.Join(renderPanel("Account view", lines, width), "\n") + "\n"
}

func resolveInspectAccount(accounts []trustpin.Account, query string) (trustpin.Account, []string, bool, bool) {
	query = normalizeAccountName(query)
	if query == "" {
		return trustpin.Account{}, nil, false, false
	}

	exactMatches := make([]trustpin.Account, 0)
	partialMatches := make([]trustpin.Account, 0)

	for _, account := range accounts {
		full := normalizeAccountName(account.Name)
		issuer, label, _ := trustpin.SplitAccountName(account.Name)
		labelKey := normalizeAccountName(label)
		issuerKey := normalizeAccountName(issuer)

		if full == query || labelKey == query || issuerKey == query {
			exactMatches = append(exactMatches, account)
			continue
		}

		haystack := strings.Join([]string{full, labelKey, issuerKey}, " ")
		if containsAllTerms(haystack, strings.Fields(query)) {
			partialMatches = append(partialMatches, account)
		}
	}

	if len(exactMatches) == 1 {
		return exactMatches[0], nil, true, false
	}
	if len(exactMatches) > 1 {
		return trustpin.Account{}, extractAccountNames(exactMatches), false, true
	}
	if len(partialMatches) == 1 {
		return partialMatches[0], nil, true, false
	}
	if len(partialMatches) > 1 {
		return trustpin.Account{}, extractAccountNames(partialMatches), false, true
	}

	return trustpin.Account{}, extractAccountNames(accounts), false, false
}

func extractAccountNames(accounts []trustpin.Account) []string {
	names := make([]string, 0, len(accounts))
	for _, account := range accounts {
		names = append(names, account.Name)
	}
	sort.Strings(names)
	if len(names) > 6 {
		names = names[:6]
	}
	return names
}

func renderInspectFallback(query string, suggestions []string, ambiguous bool) string {
	width := min(terminalWidth(), 92)
	title := "Account not found"
	message := fmt.Sprintf("No stored account matches %q.", query)
	if ambiguous {
		title = "More than one account matched"
		message = fmt.Sprintf("The query %q is ambiguous. Try the full account name.", query)
	}

	lines := []string{
		brandText("TRUSTPIN") + " " + headingText("ACCOUNT INSPECTOR"),
		mutedText(message),
	}

	if len(suggestions) > 0 {
		lines = append(lines, "")
		lines = append(lines, mutedText("Suggestions:"))
		for _, suggestion := range suggestions {
			lines = append(lines, "  - "+suggestion)
		}
	}

	lines = append(lines, "")
	lines = append(lines, mutedText("Tip: use `trustpin show --sort name --once` to scan account names quickly."))

	return strings.Join(renderPanel(title, lines, width), "\n") + "\n"
}

func renderMetricBadge(tone, label string) string {
	return styleTone(tone, "[ "+label+" ]")
}

func renderHealthBadge(level trustpin.HealthLevel, label string) string {
	switch level {
	case trustpin.HealthLevelCritical:
		return dangerText("[ " + label + " ]")
	case trustpin.HealthLevelWarning:
		return warningText("[ " + label + " ]")
	default:
		return accentText("[ " + label + " ]")
	}
}

func styleHealthHeading(level trustpin.HealthLevel, value string) string {
	switch level {
	case trustpin.HealthLevelCritical:
		return dangerText(strings.ToUpper(string(level)) + " | " + value)
	case trustpin.HealthLevelWarning:
		return warningText(strings.ToUpper(string(level)) + " | " + value)
	default:
		return accentText(strings.ToUpper(string(level)) + " | " + value)
	}
}

func styleTone(tone, value string) string {
	switch tone {
	case toneSuccess:
		return successText(value)
	case toneWarning:
		return warningText(value)
	case toneDanger:
		return dangerText(value)
	case toneMuted:
		return mutedText(value)
	default:
		return accentText(value)
	}
}

func renderPanel(title string, lines []string, width int) []string {
	width = max(width, 28)
	inner := width - 4

	border := borderText("+" + strings.Repeat("-", width-2) + "+")
	out := []string{border}
	if title != "" {
		out = append(out, borderText("| ")+padRight(headingText(truncateText(title, inner)), inner)+borderText(" |"))
		out = append(out, borderText("|")+borderText(strings.Repeat("-", width-2))+borderText("|"))
	}

	for _, line := range lines {
		out = append(out, borderText("| ")+padRight(line, inner)+borderText(" |"))
	}

	out = append(out, border)
	return out
}

func printUpsertSummary(title string, summary trustpin.UpsertSummary) {
	width := min(terminalWidth(), 88)
	lines := []string{
		strings.Join([]string{
			renderMetricBadge(toneSuccess, fmt.Sprintf("%d added", summary.Added)),
			renderMetricBadge(toneAccent, fmt.Sprintf("%d replaced", summary.Replaced)),
		}, " "),
	}

	for _, change := range summary.Changes {
		lines = append(lines, styleTone(map[string]string{"added": toneSuccess, "replaced": toneAccent}[change.Action], strings.ToUpper(change.Action))+"  "+change.Name)
	}

	fmt.Println(strings.Join(renderPanel(title, lines, width), "\n"))
}

func printImportSummary(source string, summary trustpin.UpsertSummary, skipped []string) {
	width := min(terminalWidth(), 92)
	lines := []string{
		mutedText("Imported from " + source),
		"",
		strings.Join([]string{
			renderMetricBadge(toneSuccess, fmt.Sprintf("%d added", summary.Added)),
			renderMetricBadge(toneAccent, fmt.Sprintf("%d replaced", summary.Replaced)),
			renderMetricBadge(toneWarning, fmt.Sprintf("%d skipped", len(skipped))),
		}, " "),
	}

	for _, change := range summary.Changes {
		lines = append(lines, styleTone(map[string]string{"added": toneSuccess, "replaced": toneAccent}[change.Action], strings.ToUpper(change.Action))+"  "+change.Name)
	}

	if len(skipped) > 0 {
		lines = append(lines, "")
		lines = append(lines, warningText("SKIPPED"))
		for _, item := range skipped {
			lines = append(lines, truncateText(item, width-4))
		}
	}

	fmt.Println(strings.Join(renderPanel("QR import complete", lines, width), "\n"))
}

func sanitizeAccount(account trustpin.Account) trustpin.Account {
	if account.Interval <= 0 {
		account.Interval = trustpin.DefaultInterval
	}
	if account.Digits <= 0 {
		account.Digits = trustpin.DefaultDigits
	}
	return account
}

func progressBar(percent, width int) string {
	if width <= 0 {
		return ""
	}
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}

	filled := int(float64(width) * (float64(percent) / 100))
	return "[" + strings.Repeat("#", filled) + strings.Repeat("-", width-filled) + "]"
}

func normalizeAccountName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}
