package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/saqreed/argusgate/argusgate/baseline"
	"github.com/saqreed/argusgate/argusgate/internal/fileio"
	"github.com/saqreed/argusgate/argusgate/internal/redact"
	"github.com/saqreed/argusgate/argusgate/policy"
	"github.com/saqreed/argusgate/argusgate/report"
	"github.com/saqreed/argusgate/argusgate/scanner"
	"github.com/saqreed/argusgate/argusgate/scanner/severity"
)

type scanOptions struct {
	policyPath   string
	reportPath   string
	sarifPath    string
	baselinePath string
	failOn       string
	format       string
	quiet        bool
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
	case "inspect":
		return runInspect(args[1:], stdout, stderr)
	case "baseline":
		return runBaseline(args[1:], stdout, stderr)
	case "rules":
		return runRules(args[1:], stdout, stderr)
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
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if err := rejectUnexpectedArgs(fs); err != nil {
		writeCLIError(stderr, err)
		return 2
	}
	if *configPath == "" {
		fmt.Fprintln(stderr, "scan requires --config <path>")
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
	if err := validateOutputPaths(*configPath, opts.policyPath, opts.baselinePath, opts.reportPath, opts.sarifPath); err != nil {
		writeCLIError(stderr, err)
		return 2
	}
	r, err := scanner.ScanConfigWithOptions(*configPath, p, scanner.Options{
		Baseline: loadedBaseline, BaselinePath: opts.baselinePath,
	})
	if err != nil {
		writeCLIError(stderr, err)
		return 2
	}
	return emitReport(r, *opts, stdout, stderr)
}

func runPolicy(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && (args[0] == "--help" || args[0] == "-h" || args[0] == "help") {
		fmt.Fprintln(stdout, "usage: argusgate policy validate --policy <path>")
		return 0
	}
	if len(args) == 0 || args[0] != "validate" {
		fmt.Fprintln(stderr, "usage: argusgate policy validate --policy <path>")
		return 2
	}
	fs := flag.NewFlagSet("policy validate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	policyPath := fs.String("policy", "", "path to policy YAML")
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
	if *policyPath == "" {
		fmt.Fprintln(stderr, "policy validate requires --policy <path>")
		return 2
	}
	p, err := policy.LoadFile(*policyPath)
	if err != nil {
		writeCLIError(stderr, err)
		return 2
	}
	fmt.Fprintf(stdout, "Policy valid: %s (fail_on=%s)\n", redact.Terminal(*policyPath), p.Defaults.FailOn)
	return 0
}

func runFixtures(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && (args[0] == "--help" || args[0] == "-h" || args[0] == "help") {
		fmt.Fprintln(stdout, "usage: argusgate fixtures scan --path <path> [--policy <path>] [--report <path>] [--sarif <path>]")
		return 0
	}
	if len(args) == 0 || args[0] != "scan" {
		fmt.Fprintln(stderr, "usage: argusgate fixtures scan --path <path> [--policy <path>] [--report <path>]")
		return 2
	}
	fs := flag.NewFlagSet("fixtures scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fixturePath := fs.String("path", "", "path to fixture JSON/YAML")
	opts := newScanOptions(fs)
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
	if *fixturePath == "" {
		fmt.Fprintln(stderr, "fixtures scan requires --path <path>")
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
	if err := validateOutputPaths(*fixturePath, opts.policyPath, opts.baselinePath, opts.reportPath, opts.sarifPath); err != nil {
		writeCLIError(stderr, err)
		return 2
	}
	r, err := scanner.ScanFixturesWithOptions(*fixturePath, p, scanner.Options{
		Baseline: loadedBaseline, BaselinePath: opts.baselinePath,
	})
	if err != nil {
		writeCLIError(stderr, err)
		return 2
	}
	return emitReport(r, *opts, stdout, stderr)
}

func newScanOptions(fs *flag.FlagSet) *scanOptions {
	opts := &scanOptions{}
	fs.StringVar(&opts.policyPath, "policy", "", "path to policy YAML")
	fs.StringVar(&opts.reportPath, "report", "", "path to write JSON report")
	fs.StringVar(&opts.sarifPath, "sarif", "", "path to write SARIF 2.1.0 report")
	fs.StringVar(&opts.baselinePath, "baseline", "", "path to reviewed ArgusGate baseline JSON")
	fs.StringVar(&opts.failOn, "fail-on", "", "override policy fail_on: low, medium, high, or critical")
	fs.StringVar(&opts.format, "format", "text", "stdout format: text, json, or sarif")
	fs.BoolVar(&opts.quiet, "quiet", false, "suppress text summary; errors still go to stderr")
	return opts
}

func loadBaseline(path string) (*baseline.File, error) {
	if path == "" {
		return nil, nil
	}
	value, err := baseline.LoadFile(path)
	if err != nil {
		return nil, err
	}
	return &value, nil
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
		writeCLIError(stderr, err)
		return 2
	}
	sarifData, err := report.SARIFBytes(r)
	if err != nil {
		writeCLIError(stderr, err)
		return 2
	}

	if opts.reportPath != "" {
		if err := fileio.WritePrivateFile(opts.reportPath, data); err != nil {
			writeCLIError(stderr, fmt.Errorf("write report %s: %w", opts.reportPath, err))
			return 2
		}
	}
	if opts.sarifPath != "" {
		if err := fileio.WritePrivateFile(opts.sarifPath, sarifData); err != nil {
			writeCLIError(stderr, fmt.Errorf("write SARIF report %s: %w", opts.sarifPath, err))
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
			fmt.Fprintf(stdout, "Report written: %s\n", redact.Terminal(opts.reportPath))
		}
		if opts.sarifPath != "" {
			fmt.Fprintf(stdout, "SARIF report written: %s\n", redact.Terminal(opts.sarifPath))
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
  argusgate inspect --url <https-url> [scan flags] [--timeout 15s] [--token-env ENV] [--header-env Header=ENV]
  argusgate baseline create (--config <path> | --fixtures <path> | --url <https-url>) --output <path>
  argusgate baseline update (--config <path> | --fixtures <path> | --url <https-url>) --baseline <path>
  argusgate rules list [--format text|json]
  argusgate rules show <rule-id> [--format text|json]

Commands:
  scan            Scan a local MCP-style config file. Does not start servers or execute commands.
  policy validate Validate policy syntax and severity thresholds.
  fixtures scan   Scan local MCP tool metadata fixtures for detector development and CI.
  inspect         Read metadata from an explicitly selected HTTPS MCP endpoint. Never calls tools or reads resources.
  baseline        Create or update a reviewed metadata baseline for drift and rug-pull detection.
  rules           List detector, policy, baseline, and scanner rule metadata.

Scan flags:
  --policy <path>   Optional YAML policy. Missing policy uses safe MVP defaults.
  --report <path>   Optional JSON report output path.
  --sarif <path>    Optional SARIF 2.1.0 report output path.
  --baseline <path> Optional reviewed baseline used to detect metadata drift.
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

func writeCLIError(w io.Writer, err error) {
	fmt.Fprintln(w, redact.Terminal(err.Error()))
}

func rejectUnexpectedArgs(fs *flag.FlagSet) error {
	if fs.NArg() == 0 {
		return nil
	}
	return fmt.Errorf("unexpected argument(s): %s", strings.Join(fs.Args(), " "))
}

func validateOutputPaths(inputPath, policyPath, baselinePath, reportPath, sarifPath string) error {
	outputs := []struct {
		name string
		path string
	}{
		{"--report", reportPath},
		{"--sarif", sarifPath},
	}
	inputs := []struct {
		name string
		path string
	}{
		{"scan input", inputPath},
		{"policy", policyPath},
		{"baseline", baselinePath},
	}

	for _, output := range outputs {
		if output.path == "" {
			continue
		}
		for _, input := range inputs {
			if input.path == "" {
				continue
			}
			equal, err := samePath(output.path, input.path)
			if err != nil {
				return fmt.Errorf("validate %s path: %w", output.name, err)
			}
			if equal {
				return fmt.Errorf("%s path must not overwrite %s: %s", output.name, input.name, output.path)
			}
		}
	}
	if reportPath != "" && sarifPath != "" {
		equal, err := samePath(reportPath, sarifPath)
		if err != nil {
			return fmt.Errorf("compare output paths: %w", err)
		}
		if equal {
			return fmt.Errorf("--report and --sarif must use different paths")
		}
	}
	return nil
}

func samePath(left, right string) (bool, error) {
	leftPath, err := canonicalPath(left)
	if err != nil {
		return false, err
	}
	rightPath, err := canonicalPath(right)
	if err != nil {
		return false, err
	}
	if runtime.GOOS == "windows" {
		return strings.EqualFold(leftPath, rightPath), nil
	}
	return leftPath == rightPath, nil
}

func canonicalPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return filepath.Clean(resolved), nil
	}
	parent := filepath.Dir(abs)
	if resolvedParent, err := filepath.EvalSymlinks(parent); err == nil {
		return filepath.Join(resolvedParent, filepath.Base(abs)), nil
	}
	return filepath.Clean(abs), nil
}
