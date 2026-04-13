package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/milan604/trustPIN/internal/trustpin"
	"github.com/milan604/trustPIN/internal/webui"
	"github.com/spf13/cobra"
)

type App struct {
	storePath string
}

func NewRootCmd(service trustpin.Service) *cobra.Command {
	app := &App{storePath: service.StorePath}

	rootCmd := &cobra.Command{
		Use:          "trustpin",
		Short:        "Secure TOTP workspace with terminal and web dashboards",
		Long:         "TrustPIN is a local-first TOTP workspace for importing, monitoring, and auditing one-time-password accounts in polished terminal and browser dashboards.",
		SilenceUsage: true,
		RunE:         app.runShowCommand,
	}

	rootCmd.PersistentFlags().StringVar(&app.storePath, "accounts-file", service.StorePath, "Path to the TrustPIN encrypted account store")

	addCmd := &cobra.Command{
		Use:          "add [account] [secret]",
		Short:        "Add a new TOTP account or import from a QR image",
		Long:         "Add a new TOTP account from a name and secret, or import one or more accounts from a QR image file.",
		SilenceUsage: true,
		Args:         cobra.MaximumNArgs(2),
		RunE:         app.addAccount,
	}

	showCmd := &cobra.Command{
		Use:          "show [search terms]",
		Aliases:      []string{"dashboard", "ls"},
		Short:        "Open the live TrustPIN dashboard",
		Long:         "Show TrustPIN accounts in a live dashboard with filtering, sorting, and a more readable OTP layout.",
		SilenceUsage: true,
		Args:         cobra.ArbitraryArgs,
		RunE:         app.runShowCommand,
	}

	inspectCmd := &cobra.Command{
		Use:          "inspect <account>",
		Aliases:      []string{"view"},
		Short:        "Open a focused live view for one account",
		Long:         "Inspect a single account with a dedicated OTP view, account metadata, and refresh cycle details.",
		SilenceUsage: true,
		Args:         cobra.MinimumNArgs(1),
		RunE:         app.runInspectCommand,
	}

	healthCmd := &cobra.Command{
		Use:          "health",
		Aliases:      []string{"audit"},
		Short:        "Audit account quality and security hygiene",
		Long:         "Analyze TrustPIN accounts for invalid secrets, duplicate entries, risky custom policies, and naming quality.",
		SilenceUsage: true,
		RunE:         app.runHealthCommand,
	}

	deleteCmd := &cobra.Command{
		Use:          "delete [account ...]",
		Aliases:      []string{"rm"},
		Short:        "Delete one or more TOTP accounts",
		Long:         "Delete one or more accounts by name. Running delete with no account names removes all accounts after confirmation.",
		SilenceUsage: true,
		Args:         cobra.ArbitraryArgs,
		RunE:         app.deleteAccounts,
	}

	migrateCmd := &cobra.Command{
		Use:          "migrate [legacy-accounts.json]",
		Short:        "Migrate a legacy plaintext accounts.json into encrypted storage",
		Long:         "Import a legacy plaintext TrustPIN accounts.json file into the encrypted TrustPIN store. If no path is provided, TrustPIN uses ./accounts.json from the current directory.",
		SilenceUsage: true,
		Args:         cobra.MaximumNArgs(1),
		RunE:         app.runMigrateCommand,
	}

	serveCmd := &cobra.Command{
		Use:          "serve",
		Aliases:      []string{"web", "ui"},
		Short:        "Launch the TrustPIN web dashboard",
		Long:         "Start a local web server with a modern browser-based dashboard for viewing and managing TOTP accounts.",
		SilenceUsage: true,
		RunE:         app.runServeCommand,
	}

	addCmd.Flags().IntP("interval", "i", trustpin.DefaultInterval, "Rotation interval in seconds")
	addCmd.Flags().IntP("digits", "d", trustpin.DefaultDigits, "Number of TOTP digits")
	addCmd.Flags().StringP("qr-file", "q", "", "Path to a QR image file containing an otpauth payload")

	configureShowFlags(rootCmd)
	configureShowFlags(showCmd)

	inspectCmd.Flags().Bool("watch", true, "Keep the inspect view live and refresh every second")
	inspectCmd.Flags().Bool("once", false, "Render one snapshot and exit")

	deleteCmd.Flags().BoolP("force", "f", false, "Delete without confirmation when removing all accounts")
	migrateCmd.Flags().Bool("keep-source", false, "Keep the plaintext source file after successful migration")
	serveCmd.Flags().IntP("port", "p", 8086, "Port for the web server")

	rootCmd.AddCommand(addCmd, showCmd, inspectCmd, healthCmd, deleteCmd, migrateCmd, serveCmd)
	return rootCmd
}

func configureShowFlags(cmd *cobra.Command) {
	cmd.Flags().StringP("search", "s", "", "Filter accounts by name or issuer")
	cmd.Flags().String("issuer", "", "Only show accounts for a specific issuer")
	cmd.Flags().String("sort", "expiry", "Sort by: expiry, name, issuer, digits")
	cmd.Flags().Bool("watch", true, "Keep the dashboard live and refresh every second")
	cmd.Flags().Bool("once", false, "Render one snapshot and exit")
	cmd.Flags().Bool("compact", false, "Use a denser list layout")
}

func (a *App) runShowCommand(cmd *cobra.Command, args []string) error {
	search, _ := cmd.Flags().GetString("search")
	if search == "" && len(args) > 0 {
		search = strings.Join(args, " ")
	}

	issuer, _ := cmd.Flags().GetString("issuer")
	sortBy, _ := cmd.Flags().GetString("sort")
	watch, _ := cmd.Flags().GetBool("watch")
	once, _ := cmd.Flags().GetBool("once")
	compact, _ := cmd.Flags().GetBool("compact")

	opts := showOptions{
		Search:  strings.TrimSpace(search),
		Issuer:  strings.TrimSpace(issuer),
		SortBy:  strings.TrimSpace(sortBy),
		Watch:   watch,
		Compact: compact,
	}
	if once {
		opts.Watch = false
	}

	return showDashboard(a.service(), opts)
}

func (a *App) addAccount(cmd *cobra.Command, args []string) error {
	qrFile, _ := cmd.Flags().GetString("qr-file")
	interval, _ := cmd.Flags().GetInt("interval")
	digits, _ := cmd.Flags().GetInt("digits")

	if interval <= 0 {
		return fmt.Errorf("interval must be a positive integer")
	}
	if err := trustpin.ValidateDigits(digits); err != nil {
		return err
	}

	service := a.service()
	if qrFile != "" {
		result, err := service.ImportAccountsFromQR(qrFile)
		if err != nil {
			return err
		}
		printImportSummary(qrFile, result.Summary, result.Skipped)
		return nil
	}

	account, secret, err := collectAccountInput(args)
	if err != nil {
		return err
	}
	if err := trustpin.ValidateAccountInput(account, secret); err != nil {
		return err
	}

	summary, err := service.UpsertAccounts([]trustpin.Account{{
		Name:     account,
		Secret:   secret,
		Interval: int64(interval),
		Digits:   digits,
	}})
	if err != nil {
		return err
	}

	printUpsertSummary("Account saved", summary)
	return nil
}

func (a *App) runInspectCommand(cmd *cobra.Command, args []string) error {
	watch, _ := cmd.Flags().GetBool("watch")
	once, _ := cmd.Flags().GetBool("once")
	if once {
		watch = false
	}

	return inspectAccount(a.service(), strings.Join(args, " "), watch)
}

func (a *App) runHealthCommand(cmd *cobra.Command, args []string) error {
	return showHealthReport(a.service())
}

func (a *App) runServeCommand(cmd *cobra.Command, args []string) error {
	port, _ := cmd.Flags().GetInt("port")
	if port <= 0 || port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}

	return webui.Start(a.service(), port)
}

func (a *App) runMigrateCommand(cmd *cobra.Command, args []string) error {
	service := a.service()
	keepSource, _ := cmd.Flags().GetBool("keep-source")

	source := ""
	if len(args) > 0 {
		source = args[0]
	}

	summary, err := service.MigrateLegacyFrom(source, !keepSource)
	if err != nil {
		return err
	}

	if strings.TrimSpace(source) == "" {
		source = "accounts.json"
	}

	width := min(terminalWidth(), 96)
	lines := []string{
		mutedText("Migrated from " + source),
		mutedText("Encrypted store " + service.StorePath),
		"",
		strings.Join([]string{
			renderMetricBadge(toneSuccess, fmt.Sprintf("%d added", summary.Added)),
			renderMetricBadge(toneAccent, fmt.Sprintf("%d replaced", summary.Replaced)),
		}, " "),
	}

	for _, change := range summary.Changes {
		lines = append(lines, styleTone(map[string]string{"added": toneSuccess, "replaced": toneAccent}[change.Action], strings.ToUpper(change.Action))+"  "+change.Name)
	}

	fmt.Println(strings.Join(renderPanel("Legacy migration complete", lines, width), "\n"))
	return nil
}

func (a *App) deleteAccounts(cmd *cobra.Command, args []string) error {
	force, _ := cmd.Flags().GetBool("force")
	service := a.service()

	if len(args) == 0 {
		if !force {
			confirmed, err := confirmPrompt("Delete ALL accounts")
			if err != nil {
				return err
			}
			if !confirmed {
				fmt.Println("Deletion cancelled.")
				return nil
			}
		}

		removed, err := service.DeleteAccount("all")
		if err != nil {
			return err
		}
		fmt.Printf("Deleted %d %s. TrustPIN is now empty and ready for a fresh import.\n", removed, pluralize("account", "accounts", removed))
		return nil
	}

	for _, account := range args {
		removed, err := service.DeleteAccount(account)
		if err != nil {
			return err
		}
		fmt.Printf("Deleted %d %s matching %q.\n", removed, pluralize("account", "accounts", removed), account)
	}

	return nil
}

func (a *App) service() trustpin.Service {
	return trustpin.NewService(a.storePath)
}

func collectAccountInput(args []string) (string, string, error) {
	switch len(args) {
	case 0:
		account, err := promptForValue("Account name")
		if err != nil {
			return "", "", err
		}
		secret, err := promptForValue("Secret")
		if err != nil {
			return "", "", err
		}
		return account, secret, nil
	case 1:
		secret, err := promptForValue("Secret")
		if err != nil {
			return "", "", err
		}
		return args[0], secret, nil
	default:
		return args[0], args[1], nil
	}
}

func promptForValue(label string) (string, error) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%s: ", label)
	value, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(value), nil
}

func confirmPrompt(label string) (bool, error) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%s? (y/N): ", label)
	resp, err := reader.ReadString('\n')
	if err != nil {
		return false, err
	}

	switch strings.ToLower(strings.TrimSpace(resp)) {
	case "y", "yes":
		return true, nil
	default:
		return false, nil
	}
}
