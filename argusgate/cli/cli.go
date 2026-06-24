package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/saqreed/argusgate/argusgate/policy"
	"github.com/saqreed/argusgate/argusgate/report"
	"github.com/saqreed/argusgate/argusgate/scanner"
	"github.com/saqreed/argusgate/argusgate/scanner/severity"
)

type scanOptions struct {
	policyPath string
	reportPath string
	sarifPath  string
	failOn     string
	format     string
	quiet      bool
}

func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		printHelp(stdout)
		return 0
	}
	if args[0] == "--version" || args[0] == "version" {
		fmt.Fprintf(stdout, "argusgate version %s\n", scanner.Version)
		return 0
	}

	switch args[0] {
	case "scan":
		return runScan(args[1:], stdout, stderr)
	case "policy":
		return runPolicy(args[1:], stdout, stderr)
	case "fixtures":
		return runFixtures(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n", args[0])
		printHelp(stderr)
		return 2
	}
}

func runScan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "path to MCP config JSON/YAML")
	opts := newScanOptions(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *configPath == "" {
		fmt.Fprintln(stderr, "scan requires --config <path>")
		return 2
	}

	p, err := loadPolicyOrDefault(opts.policyPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if err := applyScanOptions(&p, *opts); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	r, err := scanner.ScanConfig(*configPath, p)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	return emitReport(r, *opts, stdout, stderr)
}

func runPolicy(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "validate" {
		fmt.Fprintln(stderr, "usage: argusgate policy validate --policy <path>")
		return 2
	}
	fs := flag.NewFlagSet("policy validate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	policyPath := fs.String("policy", "", "path to policy YAML")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if *policyPath == "" {
		fmt.Fprintln(stderr, "policy validate requires --policy <path>")
		return 2
	}
	p, err := policy.LoadFile(*policyPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	fmt.Fprintf(stdout, "Policy valid: %s (fail_on=%s)\n", *policyPath, p.Defaults.FailOn)
	return 0
}

func runFixtures(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "scan" {
		fmt.Fprintln(stderr, "usage: argusgate fixtures scan --path <path> [--policy <path>] [--report <path>]")
		return 2
	}
	fs := flag.NewFlagSet("fixtures scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fixturePath := fs.String("path", "", "path to fixture JSON/YAML")
	opts := newScanOptions(fs)
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if *fixturePath == "" {
		fmt.Fprintln(stderr, "fixtures scan requires --path <path>")
		return 2
	}

	p, err := loadPolicyOrDefault(opts.policyPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if err := applyScanOptions(&p, *opts); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	r, err := scanner.ScanFixtures(*fixturePath, p)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	return emitReport(r, *opts, stdout, stderr)
}

func newScanOptions(fs *flag.FlagSet) *scanOptions {
	opts := &scanOptions{}
	fs.StringVar(&opts.policyPath, "policy", "", "path to policy YAML")
	fs.StringVar(&opts.reportPath, "report", "", "path to write JSON report")
	fs.StringVar(&opts.sarifPath, "sarif", "", "path to write SARIF 2.1.0 report")
	fs.StringVar(&opts.failOn, "fail-on", "", "override policy fail_on: low, medium, high, or critical")
	fs.StringVar(&opts.format, "format", "text", "stdout format: text, json, or sarif")
	fs.BoolVar(&opts.quiet, "quiet", false, "suppress text summary; errors still go to stderr")
	return opts
}

func loadPolicyOrDefault(path string) (policy.Policy, error) {
	if path == "" {
		return policy.Default(), nil
	}
	return policy.LoadFile(path)
}

func applyScanOptions(p *policy.Policy, opts scanOptions) error {
	opts.format = normalizeFormat(opts.format)
	switch opts.format {
	case "", "text", "json", "sarif":
	default:
		return fmt.Errorf("invalid --format %q: expected text, json, or sarif", opts.format)
	}

	if opts.failOn == "" {
		return nil
	}
	level, err := severity.Parse(opts.failOn)
	if err != nil {
		return fmt.Errorf("invalid --fail-on %q: expected low, medium, high, or critical", opts.failOn)
	}
	if level == severity.Info {
		return errors.New("invalid --fail-on \"info\": expected low, medium, high, or critical")
	}
	p.Defaults.FailOn = level
	return nil
}

func emitReport(r report.Report, opts scanOptions, stdout, stderr io.Writer) int {
	opts.format = normalizeFormat(opts.format)
	data, err := report.JSONBytes(r)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	sarifData, err := report.SARIFBytes(r)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	if opts.reportPath != "" {
		if err := os.WriteFile(opts.reportPath, data, 0o600); err != nil {
			fmt.Fprintf(stderr, "write report %s: %v\n", opts.reportPath, err)
			return 2
		}
	}
	if opts.sarifPath != "" {
		if err := os.WriteFile(opts.sarifPath, sarifData, 0o600); err != nil {
			fmt.Fprintf(stderr, "write SARIF report %s: %v\n", opts.sarifPath, err)
			return 2
		}
	}

	if opts.format == "json" {
		fmt.Fprintln(stdout, string(data))
	} else if opts.format == "sarif" {
		fmt.Fprintln(stdout, string(sarifData))
	} else if !opts.quiet {
		report.WriteTerminalSummary(stdout, r)
		if opts.reportPath != "" {
			fmt.Fprintf(stdout, "Report written: %s\n", opts.reportPath)
		}
		if opts.sarifPath != "" {
			fmt.Fprintf(stdout, "SARIF report written: %s\n", opts.sarifPath)
		}
	}

	if decision, ok := r.ExitDecision.(policy.ExitDecision); ok {
		return decision.ExitCode
	}
	return 0
}

func printHelp(w io.Writer) {
	fmt.Fprintf(w, `ArgusGate is an experimental static security scanner for MCP server configs and tool metadata.

Version: %s

Usage:
  argusgate --help
  argusgate --version
  argusgate scan --config <path> [--policy <path>] [--report <path>] [--sarif <path>] [--fail-on high] [--format text|json|sarif] [--quiet]
  argusgate policy validate --policy <path>
  argusgate fixtures scan --path <path> [--policy <path>] [--report <path>] [--sarif <path>] [--fail-on high] [--format text|json|sarif] [--quiet]

Commands:
  scan            Scan a local MCP-style config file. Does not start servers or execute commands.
  policy validate Validate policy syntax and severity thresholds.
  fixtures scan   Scan local MCP tool metadata fixtures for detector development and CI.

Scan flags:
  --policy <path>   Optional YAML policy. Missing policy uses safe MVP defaults.
  --report <path>   Optional JSON report output path.
  --sarif <path>    Optional SARIF 2.1.0 report output path.
  --fail-on <level> Override policy fail_on. Valid: low, medium, high, critical.
  --format <format> Stdout format. Valid: text, json, sarif. Default: text.
  --quiet           Suppress text summary. Errors still print to stderr.

Exit codes:
  0  no findings at or above the configured fail level
  1  findings at or above the configured fail level
  2  invalid config, invalid policy, parser error, or internal error
`, scanner.Version)
}

func normalizeFormat(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}
