package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/saqreed/argusgate/argusgate/baseline"
	"github.com/saqreed/argusgate/argusgate/inspection"
	"github.com/saqreed/argusgate/argusgate/internal/fileio"
	"github.com/saqreed/argusgate/argusgate/internal/redact"
	"github.com/saqreed/argusgate/argusgate/mcp"
	"github.com/saqreed/argusgate/argusgate/rules"
	"github.com/saqreed/argusgate/argusgate/scanner"
)

type stringListFlag []string

func (values *stringListFlag) String() string {
	return strings.Join(*values, ",")
}

func (values *stringListFlag) Set(value string) error {
	*values = append(*values, value)
	return nil
}

type inspectionFlags struct {
	serverID  string
	timeout   time.Duration
	tokenEnv  string
	headerEnv stringListFlag
}

func bindInspectionFlags(fs *flag.FlagSet) *inspectionFlags {
	options := &inspectionFlags{}
	fs.StringVar(&options.serverID, "server-id", "", "stable server identifier for reports and baselines")
	fs.DurationVar(&options.timeout, "timeout", inspection.DefaultTimeout, "total HTTPS MCP inspection timeout")
	fs.StringVar(&options.tokenEnv, "token-env", "", "environment variable containing a bearer token")
	fs.Var(&options.headerEnv, "header-env", "environment-backed header mapping Header=ENV_NAME; repeatable")
	return options
}

func (options inspectionFlags) toInspectionOptions(endpoint string) inspection.Options {
	return inspection.Options{
		URL: endpoint, ServerID: options.serverID, Timeout: options.timeout,
		TokenEnv: options.tokenEnv, HeaderEnv: options.headerEnv, ClientVersion: scanner.Version,
	}
}

func runInspect(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	endpoint := fs.String("url", "", "HTTPS Streamable HTTP MCP endpoint")
	network := bindInspectionFlags(fs)
	opts := newScanOptions(fs)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if err := rejectUnexpectedArgs(fs); err != nil {
		writeCLIError(stderr, err)
		return 2
	}
	if *endpoint == "" {
		fmt.Fprintln(stderr, "inspect requires --url <https-url>")
		return 2
	}
	p, err := loadPolicyOrDefault(opts.policyPath)
	if err != nil {
		writeCLIError(stderr, err)
		return 2
	}
	if err := applyScanOptions(&p, *opts); err != nil {
		writeCLIError(stderr, err)
		return 2
	}
	loadedBaseline, err := loadBaseline(opts.baselinePath)
	if err != nil {
		writeCLIError(stderr, err)
		return 2
	}
	if err := validateOutputPaths("", opts.policyPath, opts.baselinePath, opts.reportPath, opts.sarifPath); err != nil {
		writeCLIError(stderr, err)
		return 2
	}
	doc, err := inspection.Inspect(context.Background(), network.toInspectionOptions(*endpoint))
	if err != nil {
		writeCLIError(stderr, err)
		return 2
	}
	result, err := scanner.ScanDocumentWithOptions("live", doc, p, scanner.Options{
		Baseline: loadedBaseline, BaselinePath: opts.baselinePath,
	})
	if err != nil {
		writeCLIError(stderr, err)
		return 2
	}
	return emitReport(result, *opts, stdout, stderr)
}

type sourceFlags struct {
	config     string
	fixtures   string
	url        string
	inspection *inspectionFlags
}

func bindSourceFlags(fs *flag.FlagSet) *sourceFlags {
	source := &sourceFlags{}
	fs.StringVar(&source.config, "config", "", "local MCP config JSON/YAML")
	fs.StringVar(&source.fixtures, "fixtures", "", "local MCP metadata fixture JSON/YAML")
	fs.StringVar(&source.url, "url", "", "HTTPS Streamable HTTP MCP endpoint")
	source.inspection = bindInspectionFlags(fs)
	return source
}

func (source sourceFlags) load() (mcp.Document, string, error) {
	selected := 0
	if source.config != "" {
		selected++
	}
	if source.fixtures != "" {
		selected++
	}
	if source.url != "" {
		selected++
	}
	if selected != 1 {
		return mcp.Document{}, "", errors.New("exactly one of --config, --fixtures, or --url is required")
	}
	if source.config != "" {
		doc, err := mcp.LoadConfig(source.config)
		return doc, source.config, err
	}
	if source.fixtures != "" {
		doc, err := mcp.LoadFixtures(source.fixtures)
		return doc, source.fixtures, err
	}
	doc, err := inspection.Inspect(context.Background(), source.inspection.toInspectionOptions(source.url))
	return doc, "", err
}

func runBaseline(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		fmt.Fprintln(stdout, "usage: argusgate baseline create|update (--config <path> | --fixtures <path> | --url <https-url>) (--output <path> | --baseline <path>)")
		return 0
	}
	switch args[0] {
	case "create":
		return runBaselineCreate(args[1:], stdout, stderr)
	case "update":
		return runBaselineUpdate(args[1:], stdout, stderr)
	default:
		fmt.Fprintln(stderr, "usage: argusgate baseline create|update (--config <path> | --fixtures <path> | --url <https-url>)")
		return 2
	}
}

func runBaselineCreate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("baseline create", flag.ContinueOnError)
	fs.SetOutput(stderr)
	source := bindSourceFlags(fs)
	output := fs.String("output", "", "new baseline JSON path")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if err := rejectUnexpectedArgs(fs); err != nil {
		writeCLIError(stderr, err)
		return 2
	}
	if *output == "" {
		fmt.Fprintln(stderr, "baseline create requires --output <path>")
		return 2
	}
	doc, localInput, err := source.load()
	if err != nil {
		writeCLIError(stderr, err)
		return 2
	}
	if err := validateOutputPaths(localInput, "", "", *output, ""); err != nil {
		writeCLIError(stderr, err)
		return 2
	}
	value, err := baseline.Create(doc, scanner.Version, time.Now().UTC())
	if err != nil {
		writeCLIError(stderr, err)
		return 2
	}
	data, err := baseline.JSONBytes(value)
	if err != nil {
		writeCLIError(stderr, err)
		return 2
	}
	if err := fileio.WritePrivateFileExclusive(*output, append(data, '\n')); err != nil {
		writeCLIError(stderr, fmt.Errorf("write baseline %s: %w", *output, err))
		return 2
	}
	fmt.Fprintf(stdout, "Baseline created: %s (servers=%d artifacts=%d)\n", redact.Terminal(*output), len(value.Servers), len(value.Artifacts))
	return 0
}

func runBaselineUpdate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("baseline update", flag.ContinueOnError)
	fs.SetOutput(stderr)
	source := bindSourceFlags(fs)
	baselinePath := fs.String("baseline", "", "existing baseline JSON path")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if err := rejectUnexpectedArgs(fs); err != nil {
		writeCLIError(stderr, err)
		return 2
	}
	if *baselinePath == "" {
		fmt.Fprintln(stderr, "baseline update requires --baseline <path>")
		return 2
	}
	if _, err := baseline.LoadFile(*baselinePath); err != nil {
		writeCLIError(stderr, err)
		return 2
	}
	doc, localInput, err := source.load()
	if err != nil {
		writeCLIError(stderr, err)
		return 2
	}
	if localInput != "" {
		equal, compareErr := samePath(localInput, *baselinePath)
		if compareErr != nil {
			writeCLIError(stderr, compareErr)
			return 2
		}
		if equal {
			writeCLIError(stderr, errors.New("baseline path must not overwrite the scan source"))
			return 2
		}
	}
	value, err := baseline.Create(doc, scanner.Version, time.Now().UTC())
	if err != nil {
		writeCLIError(stderr, err)
		return 2
	}
	data, err := baseline.JSONBytes(value)
	if err != nil {
		writeCLIError(stderr, err)
		return 2
	}
	if err := fileio.WritePrivateFile(*baselinePath, append(data, '\n')); err != nil {
		writeCLIError(stderr, fmt.Errorf("update baseline %s: %w", *baselinePath, err))
		return 2
	}
	fmt.Fprintf(stdout, "Baseline updated: %s (servers=%d artifacts=%d)\n", redact.Terminal(*baselinePath), len(value.Servers), len(value.Artifacts))
	return 0
}

func runRules(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		fmt.Fprintln(stdout, "usage: argusgate rules list [--format text|json] | argusgate rules show <rule-id> [--format text|json]")
		return 0
	}
	switch args[0] {
	case "list":
		fs := flag.NewFlagSet("rules list", flag.ContinueOnError)
		fs.SetOutput(stderr)
		format := fs.String("format", "text", "output format: text or json")
		if err := fs.Parse(args[1:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return 0
			}
			return 2
		}
		if err := rejectUnexpectedArgs(fs); err != nil {
			writeCLIError(stderr, err)
			return 2
		}
		return writeRuleOutput(stdout, stderr, rules.List(), *format)
	case "show":
		fs := flag.NewFlagSet("rules show", flag.ContinueOnError)
		fs.SetOutput(stderr)
		format := fs.String("format", "text", "output format: text or json")
		showArgs := args[1:]
		ruleID := ""
		if len(showArgs) > 0 && !strings.HasPrefix(showArgs[0], "-") {
			ruleID = showArgs[0]
			showArgs = showArgs[1:]
		}
		if err := fs.Parse(showArgs); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return 0
			}
			return 2
		}
		if ruleID == "" && fs.NArg() == 1 {
			ruleID = fs.Arg(0)
		} else if fs.NArg() != 0 {
			fmt.Fprintln(stderr, "rules show requires exactly one <rule-id>")
			return 2
		}
		if ruleID == "" {
			fmt.Fprintln(stderr, "rules show requires exactly one <rule-id>")
			return 2
		}
		entry, ok := rules.Find(ruleID)
		if !ok {
			writeCLIError(stderr, fmt.Errorf("unknown rule %q", ruleID))
			return 2
		}
		return writeRuleOutput(stdout, stderr, []rules.Entry{entry}, *format)
	default:
		fmt.Fprintln(stderr, "usage: argusgate rules list|show")
		return 2
	}
}

func writeRuleOutput(stdout, stderr io.Writer, entries []rules.Entry, format string) int {
	switch normalizeFormat(format) {
	case "json":
		data, err := json.MarshalIndent(entries, "", "  ")
		if err != nil {
			writeCLIError(stderr, err)
			return 2
		}
		fmt.Fprintln(stdout, string(data))
	case "text", "":
		for _, entry := range entries {
			fmt.Fprintf(stdout, "%s [%s] %s (%s, confidence=%s)\n", entry.ID, entry.Severity, entry.Title, entry.Category, entry.Confidence)
			if len(entries) == 1 {
				if entry.OWASPMCPMapping != "" {
					fmt.Fprintf(stdout, "OWASP MCP: %s\n", entry.OWASPMCPMapping)
				}
				if entry.Recommendation != "" {
					fmt.Fprintf(stdout, "Recommendation: %s\n", entry.Recommendation)
				}
			}
		}
	default:
		writeCLIError(stderr, fmt.Errorf("invalid --format %q: expected text or json", format))
		return 2
	}
	return 0
}
