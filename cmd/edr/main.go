package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"edrsystem/internal/accountscan"
	"edrsystem/internal/environmentscan"
	"edrsystem/internal/filescan"
	"edrsystem/internal/kernelscan"
	"edrsystem/internal/portscan"
	"edrsystem/internal/processscan"
	"edrsystem/internal/riskanalysis"
	"edrsystem/internal/scheduledtaskscan"
	"edrsystem/internal/startupscan"
	"edrsystem/internal/usergroupscan"
)

func main() {
	if code := runUnifiedCLI(os.Args[1:]); code != 0 {
		os.Exit(code)
	}
}

func accountCmd(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "account \u4ec5\u652f\u6301\u5b50\u547d\u4ee4: scan")
		usage()
		os.Exit(2)
	}

	if args[0] == "-h" || args[0] == "--help" {
		usage()
		return
	}

	switch args[0] {
	case "scan":
		accountScan(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "\u672a\u77e5\u5b50\u547d\u4ee4: account %s\n", args[0])
		usage()
		os.Exit(2)
	}
}

func userGroupCmd(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "user-group \u4ec5\u652f\u6301\u5b50\u547d\u4ee4: scan")
		usage()
		os.Exit(2)
	}

	if args[0] == "-h" || args[0] == "--help" {
		usage()
		return
	}

	switch args[0] {
	case "scan":
		userGroupScan(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "\u672a\u77e5\u5b50\u547d\u4ee4: user-group %s\n", args[0])
		usage()
		os.Exit(2)
	}
}

func processCmd(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "process \u4ec5\u652f\u6301\u5b50\u547d\u4ee4: scan")
		usage()
		os.Exit(2)
	}

	if args[0] == "-h" || args[0] == "--help" {
		usage()
		return
	}

	switch args[0] {
	case "scan":
		processScan(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "\u672a\u77e5\u5b50\u547d\u4ee4: process %s\n", args[0])
		usage()
		os.Exit(2)
	}
}

type optionalBool struct {
	set   bool
	value bool
}

func (b *optionalBool) String() string {
	if !b.set {
		return ""
	}
	return strconv.FormatBool(b.value)
}

func (b *optionalBool) Set(val string) error {
	parsed, err := strconv.ParseBool(val)
	if err != nil {
		return err
	}

	b.value = parsed
	b.set = true
	return nil
}

func (b *optionalBool) IsBoolFlag() bool {
	return true
}

type optionalInt struct {
	set   bool
	value int
}

func (i *optionalInt) String() string {
	if !i.set {
		return ""
	}
	return strconv.Itoa(i.value)
}

func (i *optionalInt) Set(val string) error {
	parsed, err := strconv.Atoi(val)
	if err != nil {
		return err
	}
	i.value = parsed
	i.set = true
	return nil
}

type stringSliceFlag struct {
	set    bool
	values []string
}

func (s *stringSliceFlag) String() string {
	return strings.Join(s.values, ",")
}

func (s *stringSliceFlag) Set(val string) error {
	s.set = true
	s.values = splitCSV(val)
	return nil
}

type intSliceFlag struct {
	set    bool
	values []int
}

func (s *intSliceFlag) String() string {
	parts := make([]string, 0, len(s.values))
	for _, v := range s.values {
		parts = append(parts, strconv.Itoa(v))
	}
	return strings.Join(parts, ",")
}

func (s *intSliceFlag) Set(val string) error {
	s.set = true
	if val == "" {
		s.values = nil
		return nil
	}
	parts := splitCSV(val)
	values := make([]int, 0, len(parts))
	for _, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil {
			return fmt.Errorf("invalid value: %s", part)
		}
		values = append(values, n)
	}
	s.values = values
	return nil
}

type boolSliceFlag struct {
	set    bool
	values []bool
}

func (s *boolSliceFlag) String() string {
	parts := make([]string, 0, len(s.values))
	for _, v := range s.values {
		parts = append(parts, strconv.FormatBool(v))
	}
	return strings.Join(parts, ",")
}

func (s *boolSliceFlag) Set(val string) error {
	s.set = true
	if val == "" {
		s.values = nil
		return nil
	}
	parts := splitCSV(val)
	values := make([]bool, 0, len(parts))
	for _, part := range parts {
		b, err := strconv.ParseBool(part)
		if err != nil {
			return fmt.Errorf("invalid value: %s", part)
		}
		values = append(values, b)
	}
	s.values = values
	return nil
}

type outputModeFlag struct {
	set   bool
	value string
}

func (o *outputModeFlag) String() string {
	return o.value
}

func (o *outputModeFlag) Set(val string) error {
	o.set = true
	o.value = val
	return nil
}

func splitCSV(input string) []string {
	parts := strings.Split(input, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}

type processScanOptions struct {
	Params    processscan.ProcessScanParams
	ExcelPath string
	ShowHelp  bool
}

type accountScanOptions struct {
	Params       accountscan.AccountScanParams
	OutputFormat string
	ExcelPath    string
	ShowHelp     bool
}

type userGroupScanOptions struct {
	Params       usergroupscan.UserGroupScanParams
	OutputFormat string
	ExcelPath    string
	ShowHelp     bool
}

type portScanOptions struct {
	Params       portscan.PortScanParams
	OutputFormat string
	ExcelPath    string
	ShowHelp     bool
}

type startupScanOptions struct {
	Params       startupscan.StartupScanParams
	OutputFormat string
	ExcelPath    string
	ShowHelp     bool
}

type scheduledTaskScanOptions struct {
	Params       scheduledtaskscan.ScheduledTaskScanParams
	OutputFormat string
	ExcelPath    string
	ShowHelp     bool
}

type environmentScanOptions struct {
	Params       environmentscan.EnvironmentScanParams
	OutputFormat string
	ExcelPath    string
	ShowHelp     bool
}

type kernelScanOptions struct {
	Params       kernelscan.KernelScanParams
	OutputFormat string
	ExcelPath    string
	ShowHelp     bool
}

func parseProcessScanFlags(args []string) (processScanOptions, error) {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, "  c-eyes process scan [flags]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Options:")
		fs.PrintDefaults()
	}

	var opts processScanOptions
	var hostname, ip, startTime, packageName, state, path, uname, gname, name, startArgs, tty, description string
	var versions, packageVersions stringSliceFlag
	var pids, types intSliceFlag
	var root optionalBool
	var installedByPm optionalBool

	fs.StringVar(&hostname, "hostname", "", "Filter by hostname")
	fs.StringVar(&ip, "ip", "", "Filter by host IP address")
	fs.StringVar(&startTime, "startTime", "", "Filter by process start time (RFC3339, YYYY-MM-DD HH:MM:SS, or YYYY-MM-DD)")
	fs.Var(&versions, "versions", "Filter by process version list (comma-separated)")
	fs.Var(&root, "root", "Filter by whether the process runs as root (true/false)")
	fs.StringVar(&packageName, "packageName", "", "Filter by package name")
	fs.Var(&packageVersions, "packageVersions", "Filter by package version list (comma-separated)")
	fs.Var(&installedByPm, "installedByPm", "Filter by whether the package was installed by a package manager (true/false)")
	fs.Var(&pids, "pids", "Filter by process PID list (comma-separated)")
	fs.StringVar(&state, "state", "", "Filter by process state")
	fs.StringVar(&path, "path", "", "Filter by executable path")
	fs.StringVar(&uname, "uname", "", "Filter by owning user name")
	fs.StringVar(&gname, "gname", "", "Filter by owning group name")
	fs.StringVar(&name, "name", "", "Filter by process name")
	fs.StringVar(&startArgs, "startArgs", "", "Filter by process start arguments")
	fs.StringVar(&tty, "tty", "", "Filter by TTY")
	fs.StringVar(&description, "description", "", "Filter by process description")
	fs.Var(&types, "types", "Filter by process type list (comma-separated)")
	fs.StringVar(&opts.ExcelPath, "excel", "", "Export Excel file path (.xlsx)")

	for _, arg := range args {
		if arg == "-h" || arg == "--help" {
			opts.ShowHelp = true
			fs.Usage()
			return opts, nil
		}
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			opts.ShowHelp = true
			return opts, nil
		}
		return opts, err
	}

	params := processscan.ProcessScanParams{}
	if hostname != "" {
		params.Hostname = &hostname
	}
	if ip != "" {
		params.IP = &ip
	}
	if startTime != "" {
		parsed, err := parseTime(startTime)
		if err != nil {
			return opts, fmt.Errorf("invalid startTime: expected RFC3339, YYYY-MM-DD HH:MM:SS, or YYYY-MM-DD: %w", err)
		}
		params.StartTime = &parsed
	}
	if versions.set {
		params.Versions = versions.values
	}
	if root.set {
		params.Root = &root.value
	}
	if packageName != "" {
		params.PackageName = &packageName
	}
	if packageVersions.set {
		params.PackageVersions = packageVersions.values
	}
	if installedByPm.set {
		params.InstalledByPm = &installedByPm.value
	}
	if pids.set {
		params.PIDs = pids.values
	}
	if state != "" {
		params.State = &state
	}
	if path != "" {
		params.Path = &path
	}
	if uname != "" {
		params.Uname = &uname
	}
	if gname != "" {
		params.Gname = &gname
	}
	if name != "" {
		params.Name = &name
	}
	if startArgs != "" {
		params.StartArgs = &startArgs
	}
	if tty != "" {
		params.TTY = &tty
	}
	if description != "" {
		params.Description = &description
	}
	if types.set {
		params.Types = types.values
	}
	opts.Params = params
	return opts, nil
}
func processScan(args []string) {
	opts, err := parseProcessScanFlags(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if opts.ShowHelp {
		return
	}

	progress := newTerminalProgress(os.Stderr, "process scan")
	defer progress.Done()
	opts.Params.Progress = progress.Update

	ctx := context.Background()
	results, err := processscan.Scan(ctx, opts.Params)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if opts.ExcelPath != "" {
		if err := writeExcel(opts.ExcelPath, results); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stdout, opts.ExcelPath)
		return
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(results); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

}

func parseAccountScanFlags(args []string) (accountScanOptions, error) {
	fs := flag.NewFlagSet("account-scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, "  c-eyes account scan [flags] [-output json|excel] [-excel out.xlsx]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Options:")
		fs.PrintDefaults()
	}

	var opts accountScanOptions
	var hostname, ip, name, home, lastLoginFrom, lastLoginTo string
	output := outputModeFlag{value: "json"}
	var gid, uid string
	var groups, status intSliceFlag

	fs.Var(&groups, "groups", "Filter by group ID list (comma-separated)")
	fs.StringVar(&hostname, "hostname", "", "Filter by hostname")
	fs.StringVar(&ip, "ip", "", "Filter by host IP address")
	fs.Var(&status, "status", "Filter by account status list (comma-separated integers)")
	fs.StringVar(&name, "name", "", "Filter by account name")
	fs.StringVar(&home, "home", "", "Filter by home directory")
	fs.StringVar(&lastLoginFrom, "lastLoginFrom", "", "Filter by last login start time (RFC3339, YYYY-MM-DD HH:MM:SS, or YYYY-MM-DD)")
	fs.StringVar(&lastLoginTo, "lastLoginTo", "", "Filter by last login end time (RFC3339, YYYY-MM-DD HH:MM:SS, or YYYY-MM-DD)")
	fs.StringVar(&gid, "gid", "", "Filter by primary GID")
	fs.StringVar(&uid, "uid", "", "Filter by UID")
	fs.Var(&output, "output", "Output format: json or excel")
	fs.StringVar(&opts.ExcelPath, "excel", "", "Export Excel file path (.xlsx)")

	for _, arg := range args {
		if arg == "-h" || arg == "--help" {
			opts.ShowHelp = true
			fs.Usage()
			return opts, nil
		}
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			opts.ShowHelp = true
			return opts, nil
		}
		return opts, err
	}

	params := accountscan.AccountScanParams{}
	if groups.set {
		params.Groups = make([]int64, 0, len(groups.values))
		for _, g := range groups.values {
			params.Groups = append(params.Groups, int64(g))
		}
	}
	if hostname != "" {
		params.Hostname = &hostname
	}
	if ip != "" {
		params.IP = &ip
	}
	if status.set {
		params.Status = append(params.Status, status.values...)
	}
	if name != "" {
		params.Name = &name
	}
	if home != "" {
		params.Home = &home
	}
	if lastLoginFrom != "" || lastLoginTo != "" {
		dateRange := &accountscan.DateRange{}
		if lastLoginFrom != "" {
			from, err := parseTime(lastLoginFrom)
			if err != nil {
				return opts, fmt.Errorf("invalid lastLoginFrom: expected RFC3339, YYYY-MM-DD HH:MM:SS, or YYYY-MM-DD: %w", err)
			}
			dateRange.From = &from
		}
		if lastLoginTo != "" {
			to, err := parseTime(lastLoginTo)
			if err != nil {
				return opts, fmt.Errorf("invalid lastLoginTo: expected RFC3339, YYYY-MM-DD HH:MM:SS, or YYYY-MM-DD: %w", err)
			}
			dateRange.To = &to
		}
		params.LastLoginTime = dateRange
	}
	if gid != "" {
		parsed, err := strconv.ParseInt(gid, 10, 64)
		if err != nil {
			return opts, fmt.Errorf("invalid gid: %w", err)
		}
		params.GID = &parsed
	}
	if uid != "" {
		parsed, err := strconv.ParseInt(uid, 10, 64)
		if err != nil {
			return opts, fmt.Errorf("invalid uid: %w", err)
		}
		params.UID = &parsed
	}
	if strings.TrimSpace(opts.ExcelPath) != "" && !output.set {
		output.value = "excel"
	}

	outputMode := strings.ToLower(strings.TrimSpace(output.value))
	switch outputMode {
	case "json", "excel":
		opts.OutputFormat = outputMode
	default:
		return opts, fmt.Errorf("invalid output format: %s", output.value)
	}
	if opts.OutputFormat == "excel" && strings.TrimSpace(opts.ExcelPath) == "" {
		return opts, fmt.Errorf("excel output requires -excel <path>")
	}
	opts.Params = params
	return opts, nil
}
func accountScan(args []string) {
	opts, err := parseAccountScanFlags(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if opts.ShowHelp {
		return
	}

	progress := newTerminalProgress(os.Stderr, "account scan")
	defer progress.Done()
	opts.Params.Progress = progress.Update

	results, err := accountscan.Scan(context.Background(), opts.Params)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if opts.OutputFormat == "excel" {
		if err := writeAccountExcel(opts.ExcelPath, results.Rows); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stdout, opts.ExcelPath)
		return
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(results); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func parseUserGroupScanFlags(args []string) (userGroupScanOptions, error) {
	fs := flag.NewFlagSet("user-group-scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, "  c-eyes user-group scan [flags] [-output json|excel] [-excel out.xlsx]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Options:")
		fs.PrintDefaults()
	}

	var opts userGroupScanOptions
	var hostname, ip, name, gid string
	var groups intSliceFlag
	output := outputModeFlag{value: "json"}

	fs.Var(&groups, "groups", "Filter by group ID list (comma-separated)")
	fs.StringVar(&hostname, "hostname", "", "Filter by hostname")
	fs.StringVar(&ip, "ip", "", "Filter by host IP address")
	fs.StringVar(&name, "name", "", "Filter by user group name")
	fs.StringVar(&gid, "gid", "", "Filter by group ID")
	fs.Var(&output, "output", "Output format: json or excel")
	fs.StringVar(&opts.ExcelPath, "excel", "", "Export Excel file path (.xlsx)")

	for _, arg := range args {
		if arg == "-h" || arg == "--help" {
			opts.ShowHelp = true
			fs.Usage()
			return opts, nil
		}
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			opts.ShowHelp = true
			return opts, nil
		}
		return opts, err
	}

	params := usergroupscan.UserGroupScanParams{}
	if groups.set {
		params.Groups = make([]int64, 0, len(groups.values))
		for _, g := range groups.values {
			params.Groups = append(params.Groups, int64(g))
		}
	}
	if hostname != "" {
		params.Hostname = &hostname
	}
	if ip != "" {
		params.IP = &ip
	}
	if name != "" {
		params.Name = &name
	}
	if gid != "" {
		parsed, err := strconv.ParseInt(gid, 10, 64)
		if err != nil {
			return opts, fmt.Errorf("invalid gid: %w", err)
		}
		params.GID = &parsed
	}

	if strings.TrimSpace(opts.ExcelPath) != "" && !output.set {
		output.value = "excel"
	}

	outputMode := strings.ToLower(strings.TrimSpace(output.value))
	switch outputMode {
	case "json", "excel":
		opts.OutputFormat = outputMode
	default:
		return opts, fmt.Errorf("invalid output format: %s", output.value)
	}
	if opts.OutputFormat == "excel" && strings.TrimSpace(opts.ExcelPath) == "" {
		return opts, fmt.Errorf("excel output requires -excel <path>")
	}

	opts.Params = params
	return opts, nil
}
func userGroupScan(args []string) {
	opts, err := parseUserGroupScanFlags(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if opts.ShowHelp {
		return
	}

	progress := newTerminalProgress(os.Stderr, "user-group scan")
	defer progress.Done()
	opts.Params.Progress = progress.Update

	results, err := usergroupscan.Scan(context.Background(), opts.Params)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if opts.OutputFormat == "excel" {
		if err := writeUserGroupExcel(opts.ExcelPath, results.Rows); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stdout, opts.ExcelPath)
		return
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(results); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func parsePortScanFlags(args []string) (portScanOptions, error) {
	fs := flag.NewFlagSet("port-scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, "  c-eyes port-scan [flags] [-output json|excel] [-excel out.xlsx]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Options:")
		fs.PrintDefaults()
	}

	var opts portScanOptions
	var hostname, ip, bindIP, processName, mode string
	var groups intSliceFlag
	var protos stringSliceFlag
	var port optionalInt
	output := outputModeFlag{value: "json"}

	fs.Var(&groups, "groups", "Filter by group ID list (comma-separated)")
	fs.StringVar(&hostname, "hostname", "", "Filter by hostname")
	fs.StringVar(&ip, "ip", "", "Filter by host IP address")
	fs.Var(&protos, "proto", "Filter by protocol list (comma-separated)")
	fs.Var(&port, "port", "Filter by port number")
	fs.StringVar(&bindIP, "bindIp", "", "Filter by bind IP address")
	fs.StringVar(&processName, "processName", "", "Filter by process name")
	fs.StringVar(&mode, "mode", string(portscan.ScanModeTCPConnect), "Scan mode: connect or tcp-syn")
	fs.Var(&output, "output", "Output format: json or excel")
	fs.StringVar(&opts.ExcelPath, "excel", "", "Export Excel file path (.xlsx)")

	for _, arg := range args {
		if arg == "-h" || arg == "--help" {
			opts.ShowHelp = true
			fs.Usage()
			return opts, nil
		}
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			opts.ShowHelp = true
			return opts, nil
		}
		return opts, err
	}

	params := portscan.PortScanParams{}
	if groups.set {
		params.Groups = make([]int64, 0, len(groups.values))
		for _, g := range groups.values {
			params.Groups = append(params.Groups, int64(g))
		}
	}
	if hostname != "" {
		params.Hostname = &hostname
	}
	if ip != "" {
		params.IP = &ip
	}
	if protos.set {
		params.Protos = append(params.Protos, protos.values...)
	}
	if port.set {
		params.Port = &port.value
	}
	if bindIP != "" {
		params.BindIP = &bindIP
	}
	if processName != "" {
		params.ProcessName = &processName
	}

	normalizedMode := strings.ToLower(strings.TrimSpace(mode))
	switch normalizedMode {
	case string(portscan.ScanModeTCPConnect), string(portscan.ScanModeTCPSYN):
		params.Mode = portscan.ScanMode(normalizedMode)
	default:
		return opts, fmt.Errorf("invalid mode: %s (supported: connect/tcp-syn)", mode)
	}

	if strings.TrimSpace(opts.ExcelPath) != "" && !output.set {
		output.value = "excel"
	}

	outputMode := strings.ToLower(strings.TrimSpace(output.value))
	switch outputMode {
	case "json", "excel":
		opts.OutputFormat = outputMode
	default:
		return opts, fmt.Errorf("invalid output format: %s", output.value)
	}
	if opts.OutputFormat == "excel" && strings.TrimSpace(opts.ExcelPath) == "" {
		return opts, fmt.Errorf("excel output requires -excel <path>")
	}

	opts.Params = params
	return opts, nil
}
func portScan(args []string) {
	opts, err := parsePortScanFlags(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if opts.ShowHelp {
		return
	}

	progress := newTerminalProgress(os.Stderr, "port scan")
	defer progress.Done()
	opts.Params.Progress = progress.Update

	results, err := portscan.Scan(context.Background(), opts.Params)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if opts.OutputFormat == "excel" {
		if err := writePortScanExcel(opts.ExcelPath, results.Rows); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stdout, opts.ExcelPath)
		return
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(results); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func parseStartupScanFlags(args []string) (startupScanOptions, error) {
	fs := flag.NewFlagSet("startup-scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, "  c-eyes startup-scan [flags] [-output json|excel] [-excel out.xlsx]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Options:")
		fs.PrintDefaults()
	}

	var opts startupScanOptions
	var hostname, ip, name, showName, user, publisher string
	var groups, initLevel, startType intSliceFlag
	var defaultOpen, isXinetd boolSliceFlag
	var enable optionalBool
	output := outputModeFlag{value: "json"}

	fs.Var(&groups, "groups", "Filter by group ID list (comma-separated)")
	fs.StringVar(&hostname, "hostname", "", "Filter by hostname")
	fs.StringVar(&ip, "ip", "", "Filter by host IP address")
	fs.StringVar(&name, "name", "", "Filter by startup item name")
	fs.Var(&initLevel, "initLevel", "Filter by init level list (Linux, comma-separated integers)")
	fs.Var(&defaultOpen, "defaultOpen", "Filter by default-open flag list (Linux, comma-separated true/false)")
	fs.Var(&isXinetd, "isXinetd", "Filter by xinetd flag list (Linux, comma-separated true/false)")
	fs.StringVar(&showName, "showName", "", "Filter by display name (Windows)")
	fs.StringVar(&user, "user", "", "Filter by owning user")
	fs.Var(&enable, "enable", "Filter by enabled flag (Windows, true/false)")
	fs.Var(&startType, "startType", "Filter by start type list (Windows, comma-separated integers)")
	fs.StringVar(&publisher, "publisher", "", "Filter by publisher (Windows)")
	fs.Var(&output, "output", "Output format: json or excel")
	fs.StringVar(&opts.ExcelPath, "excel", "", "Export Excel file path (.xlsx)")

	for _, arg := range args {
		if arg == "-h" || arg == "--help" {
			opts.ShowHelp = true
			fs.Usage()
			return opts, nil
		}
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			opts.ShowHelp = true
			return opts, nil
		}
		return opts, err
	}

	params := startupscan.StartupScanParams{}
	if groups.set {
		params.Groups = make([]int64, 0, len(groups.values))
		for _, g := range groups.values {
			params.Groups = append(params.Groups, int64(g))
		}
	}
	if hostname != "" {
		params.Hostname = &hostname
	}
	if ip != "" {
		params.IP = &ip
	}
	if name != "" {
		params.Name = &name
	}
	if initLevel.set {
		params.InitLevel = append(params.InitLevel, initLevel.values...)
	}
	if defaultOpen.set {
		params.DefaultOpen = append(params.DefaultOpen, defaultOpen.values...)
	}
	if isXinetd.set {
		params.IsXinetd = append(params.IsXinetd, isXinetd.values...)
	}
	if showName != "" {
		params.ShowName = &showName
	}
	if user != "" {
		params.User = &user
	}
	if enable.set {
		params.Enable = &enable.value
	}
	if startType.set {
		params.StartType = append(params.StartType, startType.values...)
	}
	if publisher != "" {
		params.Publisher = &publisher
	}

	if strings.TrimSpace(opts.ExcelPath) != "" && !output.set {
		output.value = "excel"
	}

	outputMode := strings.ToLower(strings.TrimSpace(output.value))
	switch outputMode {
	case "json", "excel":
		opts.OutputFormat = outputMode
	default:
		return opts, fmt.Errorf("invalid output format: %s", output.value)
	}
	if opts.OutputFormat == "excel" && strings.TrimSpace(opts.ExcelPath) == "" {
		return opts, fmt.Errorf("excel output requires -excel <path>")
	}

	opts.Params = params
	return opts, nil
}
func startupScan(args []string) {
	opts, err := parseStartupScanFlags(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if opts.ShowHelp {
		return
	}

	progress := newTerminalProgress(os.Stderr, "startup scan")
	defer progress.Done()
	opts.Params.Progress = progress.Update

	results, err := startupscan.Scan(context.Background(), opts.Params)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if opts.OutputFormat == "excel" {
		if err := writeStartupScanExcel(opts.ExcelPath, results.Rows); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stdout, opts.ExcelPath)
		return
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(results); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func parseScheduledTaskScanFlags(args []string) (scheduledTaskScanOptions, error) {
	fs := flag.NewFlagSet("scheduled-task-scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, "  c-eyes scheduled-task-scan [flags] [-output json|excel] [-excel out.xlsx]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Options:")
		fs.PrintDefaults()
	}

	var opts scheduledTaskScanOptions
	var hostname, ip, execPath, conf, taskTimeFrom, taskTimeTo string
	var groups intSliceFlag
	var users, taskTypes stringSliceFlag
	output := outputModeFlag{value: "json"}

	fs.Var(&groups, "groups", "Filter by group ID list (comma-separated)")
	fs.StringVar(&hostname, "hostname", "", "Filter by hostname")
	fs.StringVar(&ip, "ip", "", "Filter by host IP address")
	fs.Var(&users, "user", "Filter by user list (comma-separated)")
	fs.StringVar(&execPath, "execPath", "", "Filter by task executable path")
	fs.StringVar(&conf, "conf", "", "Filter by task configuration path")
	fs.StringVar(&taskTimeFrom, "taskTimeFrom", "", "Filter by task start time (RFC3339, YYYY-MM-DD HH:MM:SS, or YYYY-MM-DD)")
	fs.StringVar(&taskTimeTo, "taskTimeTo", "", "Filter by task end time (RFC3339, YYYY-MM-DD HH:MM:SS, or YYYY-MM-DD)")
	fs.Var(&taskTypes, "taskType", "Filter by task type list (comma-separated, supported: CRONTAB/AT/BATCH)")
	fs.Var(&output, "output", "Output format: json or excel")
	fs.StringVar(&opts.ExcelPath, "excel", "", "Export Excel file path (.xlsx)")

	for _, arg := range args {
		if arg == "-h" || arg == "--help" {
			opts.ShowHelp = true
			fs.Usage()
			return opts, nil
		}
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			opts.ShowHelp = true
			return opts, nil
		}
		return opts, err
	}

	params := scheduledtaskscan.ScheduledTaskScanParams{}
	if groups.set {
		params.Groups = make([]int64, 0, len(groups.values))
		for _, g := range groups.values {
			params.Groups = append(params.Groups, int64(g))
		}
	}
	if hostname != "" {
		params.Hostname = &hostname
	}
	if ip != "" {
		params.IP = &ip
	}
	if users.set {
		params.User = append(params.User, users.values...)
	}
	if execPath != "" {
		params.ExecPath = &execPath
	}
	if conf != "" {
		params.Conf = &conf
	}
	if taskTimeFrom != "" || taskTimeTo != "" {
		dr := &scheduledtaskscan.DateRange{}
		if taskTimeFrom != "" {
			from, err := parseTime(taskTimeFrom)
			if err != nil {
				return opts, fmt.Errorf("invalid taskTimeFrom: expected RFC3339, YYYY-MM-DD HH:MM:SS, or YYYY-MM-DD: %w", err)
			}
			dr.From = &from
		}
		if taskTimeTo != "" {
			to, err := parseTime(taskTimeTo)
			if err != nil {
				return opts, fmt.Errorf("invalid taskTimeTo: expected RFC3339, YYYY-MM-DD HH:MM:SS, or YYYY-MM-DD: %w", err)
			}
			dr.To = &to
		}
		params.TaskTime = dr
	}
	if taskTypes.set {
		for _, taskType := range taskTypes.values {
			normalized := strings.ToUpper(strings.TrimSpace(taskType))
			if !scheduledtaskscan.IsSupportedTaskType(normalized) {
				return opts, fmt.Errorf("taskType parameter invalid: %s (supported: CRONTAB/AT/BATCH)", taskType)
			}
			params.TaskType = append(params.TaskType, normalized)
		}
	}

	if strings.TrimSpace(opts.ExcelPath) != "" && !output.set {
		output.value = "excel"
	}

	outputMode := strings.ToLower(strings.TrimSpace(output.value))
	switch outputMode {
	case "json", "excel":
		opts.OutputFormat = outputMode
	default:
		return opts, fmt.Errorf("invalid output format: %s", output.value)
	}
	if opts.OutputFormat == "excel" && strings.TrimSpace(opts.ExcelPath) == "" {
		return opts, fmt.Errorf("excel output requires -excel <path>")
	}

	opts.Params = params
	return opts, nil
}
func scheduledTaskScan(args []string) {
	opts, err := parseScheduledTaskScanFlags(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if opts.ShowHelp {
		return
	}

	progress := newTerminalProgress(os.Stderr, "scheduled-task scan")
	defer progress.Done()
	opts.Params.Progress = progress.Update

	results, err := scheduledtaskscan.Scan(context.Background(), opts.Params)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if opts.OutputFormat == "excel" {
		if err := writeScheduledTaskScanExcel(opts.ExcelPath, results.Rows); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stdout, opts.ExcelPath)
		return
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(results); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func parseEnvironmentScanFlags(args []string) (environmentScanOptions, error) {
	fs := flag.NewFlagSet("environment-scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, "  c-eyes environment-scan [flags] [-output json|excel] [-excel out.xlsx]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Options:")
		fs.PrintDefaults()
	}

	var opts environmentScanOptions
	var hostname, ip, key, value, user string
	var groups intSliceFlag
	var sysEnv boolSliceFlag
	output := outputModeFlag{value: "json"}

	fs.Var(&groups, "groups", "Filter by group ID list (comma-separated)")
	fs.StringVar(&hostname, "hostname", "", "Filter by hostname")
	fs.StringVar(&ip, "ip", "", "Filter by host IP address")
	fs.StringVar(&key, "key", "", "Filter by environment variable key")
	fs.StringVar(&value, "value", "", "Filter by environment variable value")
	fs.StringVar(&user, "user", "", "Filter by owning user")
	fs.Var(&sysEnv, "sysEnv", "Filter by system environment variable flag (comma-separated true/false)")
	fs.Var(&output, "output", "Output format: json or excel")
	fs.StringVar(&opts.ExcelPath, "excel", "", "Export Excel file path (.xlsx)")

	for _, arg := range args {
		if arg == "-h" || arg == "--help" {
			opts.ShowHelp = true
			fs.Usage()
			return opts, nil
		}
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			opts.ShowHelp = true
			return opts, nil
		}
		return opts, err
	}

	params := environmentscan.EnvironmentScanParams{}
	if groups.set {
		params.Groups = make([]int64, 0, len(groups.values))
		for _, g := range groups.values {
			params.Groups = append(params.Groups, int64(g))
		}
	}
	if hostname != "" {
		params.Hostname = &hostname
	}
	if ip != "" {
		params.IP = &ip
	}
	if key != "" {
		params.Key = &key
	}
	if value != "" {
		params.Value = &value
	}
	if user != "" {
		params.User = &user
	}
	if sysEnv.set {
		params.SysEnv = append(params.SysEnv, sysEnv.values...)
	}

	if strings.TrimSpace(opts.ExcelPath) != "" && !output.set {
		output.value = "excel"
	}

	outputMode := strings.ToLower(strings.TrimSpace(output.value))
	switch outputMode {
	case "json", "excel":
		opts.OutputFormat = outputMode
	default:
		return opts, fmt.Errorf("invalid output format: %s", output.value)
	}
	if opts.OutputFormat == "excel" && strings.TrimSpace(opts.ExcelPath) == "" {
		return opts, fmt.Errorf("excel output requires -excel <path>")
	}

	opts.Params = params
	return opts, nil
}
func environmentScan(args []string) {
	opts, err := parseEnvironmentScanFlags(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if opts.ShowHelp {
		return
	}

	progress := newTerminalProgress(os.Stderr, "environment scan")
	defer progress.Done()
	opts.Params.Progress = progress.Update

	results, err := environmentscan.Scan(context.Background(), opts.Params)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if opts.OutputFormat == "excel" {
		if err := writeEnvironmentScanExcel(opts.ExcelPath, results.Rows); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stdout, opts.ExcelPath)
		return
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(results); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func parseKernelScanFlags(args []string) (kernelScanOptions, error) {
	fs := flag.NewFlagSet("kernel-scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, "  c-eyes kernel-scan [flags] [-output json|excel] [-excel out.xlsx]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Options:")
		fs.PrintDefaults()
	}

	var opts kernelScanOptions
	var hostname, ip, moduleName, path string
	var groups intSliceFlag
	var version stringSliceFlag
	output := outputModeFlag{value: "json"}

	fs.Var(&groups, "groups", "Filter by group ID list (comma-separated)")
	fs.StringVar(&hostname, "hostname", "", "Filter by hostname")
	fs.StringVar(&ip, "ip", "", "Filter by host IP address")
	fs.StringVar(&moduleName, "moduleName", "", "Filter by kernel module name")
	fs.StringVar(&path, "path", "", "Filter by kernel module path")
	fs.Var(&version, "version", "Filter by kernel/module version list (comma-separated)")
	fs.Var(&output, "output", "Output format: json or excel")
	fs.StringVar(&opts.ExcelPath, "excel", "", "Export Excel file path (.xlsx)")

	for _, arg := range args {
		if arg == "-h" || arg == "--help" {
			opts.ShowHelp = true
			fs.Usage()
			return opts, nil
		}
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			opts.ShowHelp = true
			return opts, nil
		}
		return opts, err
	}

	params := kernelscan.KernelScanParams{}
	if groups.set {
		params.Groups = make([]int64, 0, len(groups.values))
		for _, g := range groups.values {
			params.Groups = append(params.Groups, int64(g))
		}
	}
	if hostname != "" {
		params.Hostname = &hostname
	}
	if ip != "" {
		params.IP = &ip
	}
	if moduleName != "" {
		params.ModuleName = &moduleName
	}
	if path != "" {
		params.Path = &path
	}
	if version.set {
		params.Version = append(params.Version, version.values...)
	}

	if strings.TrimSpace(opts.ExcelPath) != "" && !output.set {
		output.value = "excel"
	}

	outputMode := strings.ToLower(strings.TrimSpace(output.value))
	switch outputMode {
	case "json", "excel":
		opts.OutputFormat = outputMode
	default:
		return opts, fmt.Errorf("invalid output format: %s", output.value)
	}
	if opts.OutputFormat == "excel" && strings.TrimSpace(opts.ExcelPath) == "" {
		return opts, fmt.Errorf("excel output requires -excel <path>")
	}

	opts.Params = params
	return opts, nil
}
func kernelScan(args []string) {
	opts, err := parseKernelScanFlags(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if opts.ShowHelp {
		return
	}

	progress := newTerminalProgress(os.Stderr, "kernel scan")
	defer progress.Done()
	opts.Params.Progress = progress.Update

	results, err := kernelscan.Scan(context.Background(), opts.Params)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if opts.OutputFormat == "excel" {
		if err := writeKernelScanExcel(opts.ExcelPath, results.Rows); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stdout, opts.ExcelPath)
		return
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(results); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func parseTime(value string) (time.Time, error) {
	formats := []string{
		time.RFC3339,
		"2006-01-02 15:04:05",
		"2006-01-02",
	}
	for _, layout := range formats {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed, nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid argument")
}

func fileCmd(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "file \u4ec5\u652f\u6301\u5b50\u547d\u4ee4: scan")
		usage()
		os.Exit(2)
	}

	if args[0] == "-h" || args[0] == "--help" {
		usage()
		return
	}

	switch args[0] {
	case "scan":
		fileScan(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "\u672a\u77e5\u5b50\u547d\u4ee4: file %s\n", args[0])
		usage()
		os.Exit(2)
	}
}

func riskCmd(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "risk \u4ec5\u652f\u6301\u5b50\u547d\u4ee4: analyze")
		usage()
		os.Exit(2)
	}

	if args[0] == "-h" || args[0] == "--help" {
		usage()
		return
	}

	switch args[0] {
	case "analyze":
		riskAnalyze(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "\u672a\u77e5\u5b50\u547d\u4ee4: risk %s\n", args[0])
		usage()
		os.Exit(2)
	}
}

type riskOptions struct {
	InputPath              string
	FilePath               string
	DirPath                string
	ProcessPID             int
	ProcessName            string
	ProcessMemory          bool
	MemoryMaxBytes         int
	Mode                   string
	ExcelPath              string
	JSONPath               string
	YaraRules              string
	YaraReadChunk          int
	LocalWeight            float64
	CloudWeight            float64
	CloudUpload            bool
	CloudUploadConcurrency int
	CloudUploadWait        time.Duration
	CloudUploadSubmitTO    time.Duration
	CloudUploadPollEvery   time.Duration
	CloudUploadMaxSize     int64
	AnalysisMaxDuration    time.Duration
	ShowHelp               bool
}

func normalizeRiskFlagAliases(args []string) []string {
	normalized := make([]string, 0, len(args))
	for _, arg := range args {
		switch {
		case arg == "-mode" || arg == "--mode":
			normalized = append(normalized, "-risk-mode")
		case strings.HasPrefix(arg, "-mode="):
			normalized = append(normalized, "-risk-mode="+strings.TrimPrefix(arg, "-mode="))
		case strings.HasPrefix(arg, "--mode="):
			normalized = append(normalized, "-risk-mode="+strings.TrimPrefix(arg, "--mode="))
		default:
			normalized = append(normalized, arg)
		}
	}
	return normalized
}

func parseRiskFlags(args []string) (riskOptions, error) {
	fs := flag.NewFlagSet("risk-analyze", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "NAME:")
		fmt.Fprintln(os.Stderr, "    c-eyes -r - Designated analysis source for anomaly analysis")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "USAGE:")
		fmt.Fprintln(os.Stderr, "    c-eyes -r -input/-file/-dir/-pid/-pname (Analysis source must be specified, choose one of the five parameters)")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "OPTIONS:")
		fmt.Fprintln(os.Stderr, "YARA rules are required for mode=local_only")
		fmt.Fprintln(os.Stderr, "  -analysis-max-duration <number(s/m/h)>    Analysis duration limit (add units, such as 30s, 5m, 1h)")
		fmt.Fprintln(os.Stderr, "  -cloud-upload                             Enable file upload cloud analysis")
		fmt.Fprintln(os.Stderr, "  -process-memory                           Enable collection of process memory samples (only supported with -pid/-pname)")
		fmt.Fprintln(os.Stderr, "  --risk-mode <mode>                        Risk analysis mode: local_only / cloud_only / fast / smart / deep")
		fmt.Fprintln(os.Stderr, "  -input <scan.json/scan.csv/scan.xlsx>     Use existing scan result file as analysis source")
		fmt.Fprintln(os.Stderr, "  -file <path>                              Use a single file path as analysis source")
		fmt.Fprintln(os.Stderr, "  -dir <path>                               Use a directory path as analysis source")
		fmt.Fprintln(os.Stderr, "  -pid <pid>                                Use process PID as analysis source")
		fmt.Fprintln(os.Stderr, "  -pname <process_name>                     Use process name as analysis source")
	}

	normalizedArgs := normalizeRiskFlagAliases(args)
	var opts riskOptions
	opts.ProcessPID = -1
	opts.MemoryMaxBytes = riskanalysis.DefaultProcessMemoryMaxBytes
	opts.YaraReadChunk = riskanalysis.DefaultYaraReadChunkSize
	opts.LocalWeight = 0.6
	opts.CloudWeight = 0.4
	opts.CloudUploadConcurrency = 2
	opts.CloudUploadSubmitTO = 20 * time.Second
	opts.CloudUploadPollEvery = 5 * time.Second
	opts.CloudUploadMaxSize = 20 * 1024 * 1024

	fs.StringVar(&opts.InputPath, "input", "", "Input scan result file (JSON/CSV/XLSX)")
	fs.StringVar(&opts.FilePath, "file", "", "Use a single file path as analysis source")
	fs.StringVar(&opts.DirPath, "dir", "", "Use a directory path as analysis source")
	fs.IntVar(&opts.ProcessPID, "pid", -1, "Use process PID as analysis source")
	fs.StringVar(&opts.ProcessName, "pname", "", "Use process name as analysis source")
	fs.StringVar(&opts.Mode, "risk-mode", "", "Risk analysis mode: local_only/cloud_only/fast/smart/deep")
	fs.StringVar(&opts.YaraRules, "yara-rules", "", "YARA-X rules file path")
	fs.BoolVar(&opts.ProcessMemory, "process-memory", false, "Collect process memory sample too (process source only)")
	fs.BoolVar(&opts.CloudUpload, "cloud-upload", false, "Enable cloud upload for analyzable files")
	fs.DurationVar(&opts.AnalysisMaxDuration, "analysis-max-duration", 0, "Max total analysis duration (0 means unlimited)")

	for _, arg := range normalizedArgs {
		if arg == "-h" || arg == "--help" {
			opts.ShowHelp = true
			fs.Usage()
			return opts, nil
		}
	}

	if err := fs.Parse(normalizedArgs); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			opts.ShowHelp = true
			return opts, nil
		}
		return opts, err
	}
	if opts.ShowHelp {
		fs.Usage()
		return opts, nil
	}

	if opts.AnalysisMaxDuration < 0 {
		return opts, fmt.Errorf("-analysis-max-duration must be greater than or equal to 0")
	}
	if opts.ProcessPID != -1 && opts.ProcessPID <= 0 {
		return opts, fmt.Errorf("-pid must be greater than 0")
	}

	processSource := opts.ProcessPID > 0 || strings.TrimSpace(opts.ProcessName) != ""
	sourceCount := 0
	if strings.TrimSpace(opts.InputPath) != "" {
		sourceCount++
	}
	if strings.TrimSpace(opts.FilePath) != "" {
		sourceCount++
	}
	if strings.TrimSpace(opts.DirPath) != "" {
		sourceCount++
	}
	if processSource {
		sourceCount++
	}

	if sourceCount == 0 {
		return opts, fmt.Errorf("analysis source is required: choose one of -input/-file/-dir/-pid/-pname")
	}
	if sourceCount > 1 {
		return opts, fmt.Errorf("analysis source parameters are mutually exclusive: choose only one of -input/-file/-dir/-pid/-pname")
	}

	if opts.ProcessMemory && !processSource {
		return opts, fmt.Errorf("-process-memory is only supported with -pid/-pname")
	}

	return opts, nil
}

func resolveRiskMode(mode string) (riskanalysis.AnalysisMode, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode != "" {
		switch riskanalysis.AnalysisMode(mode) {
		case riskanalysis.ModeLocalOnly, riskanalysis.ModeCloudOnly, riskanalysis.ModeFast, riskanalysis.ModeSmart, riskanalysis.ModeDeep:
			return riskanalysis.AnalysisMode(mode), nil
		case riskanalysis.ModeHybrid:
			fmt.Fprintln(os.Stderr, "mode=hybrid is deprecated; using mode=smart")
			return riskanalysis.ModeSmart, nil
		default:
			return "", fmt.Errorf("invalid value: %s", mode)
		}
	}

	return riskanalysis.ModeSmart, nil
}

func riskAnalyze(args []string) {
	opts, err := parseRiskFlags(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if opts.ShowHelp {
		return
	}

	mode, err := resolveRiskMode(opts.Mode)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	currentHostname, _ := os.Hostname()

	var localMatcher riskanalysis.LocalMatcher
	if mode == riskanalysis.ModeLocalOnly || mode == riskanalysis.ModeFast || mode == riskanalysis.ModeSmart || mode == riskanalysis.ModeDeep {
		rules := opts.YaraRules
		if rules == "" {
			if envRules := os.Getenv("C_EYES_YARA_RULES"); envRules != "" {
				rules = envRules
			}
		}
		if rules == "" {
			rules = defaultRulesPath()
		}
		if rules == "" {
			if mode == riskanalysis.ModeLocalOnly {
				fmt.Fprintln(os.Stderr, "YARA rules are required for mode=local_only")
				os.Exit(2)
			}
			fmt.Fprintln(os.Stderr, "YARA rules are required for mode=local_only")
		}
		if rules != "" {
			engine, err := riskanalysis.NewYaraXEngine(riskanalysis.YaraXConfig{
				RulesPath:     rules,
				ReadChunkSize: opts.YaraReadChunk,
			})
			if err != nil {
				if mode == riskanalysis.ModeLocalOnly {
					fmt.Fprintf(os.Stderr, "local YARA engine initialization failed: %v`n", err)
					os.Exit(2)
				}
				fmt.Fprintf(os.Stderr, "local YARA engine initialization failed: %v`n", err)
			} else {
				if warning := riskanalysis.YaraXEngineWarning(engine); warning != "" {
					if mode == riskanalysis.ModeLocalOnly {
						fmt.Fprintf(os.Stderr, "local YARA engine warning: %s`n", warning)
						os.Exit(2)
					}
					fmt.Fprintf(os.Stderr, "local YARA engine warning: %s`n", warning)
				} else {
					localMatcher = &riskanalysis.YaraXMatcher{
						Engine:          engine,
						CurrentHostname: currentHostname,
					}
				}
			}
		}
	}

	var cloudClient riskanalysis.CloudClient
	if mode != riskanalysis.ModeLocalOnly {
		cfg, cfgPath, cfgErr := riskanalysis.LoadCloudConfig()
		if cfgErr != nil {
			if cfgPath != "" {
				fmt.Fprintf(os.Stderr, "failed to load cloud configuration (%s): %v\n", cfgPath, cfgErr)
			} else {
				fmt.Fprintf(os.Stderr, "failed to load cloud configuration: %v\n", cfgErr)
			}
			os.Exit(2)
		}
		providers := []string{"virustotal", "hybrid_analysis", "malwarebazaar", "otx", "triage"}
		clients := make([]riskanalysis.CloudProviderClient, 0, len(providers))
		uploadPolicy := make(map[string]bool, len(providers))
		for _, provider := range providers {
			providerCfg := providerConfigFromFile(cfg, provider)
			uploadPolicy[provider] = providerCfg.UploadEnabledOrDefault(provider)
			apiKey := providerCfg.APIKey
			if apiKey == "" {
				apiKey = os.Getenv("C_EYES_CLOUD_API_KEY")
			}
			if apiKey == "" {
				apiKey = providerEnvFallback(provider)
			}

			baseURL := providerCfg.BaseURL

			proxyURL := providerCfg.ProxyURL
			if proxyURL == "" && cfg != nil && cfg.ProxyURL != "" {
				proxyURL = cfg.ProxyURL
			}

			rateLimit := 2 * time.Second
			if providerCfg.RateLimit != "" {
				if d, err := providerCfg.RateLimitDuration(); err != nil {
					fmt.Fprintf(os.Stderr, "cloud provider %s has invalid rate-limit configuration: %v`n", provider, err)
				} else {
					rateLimit = d
				}
			}
			if opts.CloudUpload && providerCfg.UploadRateLimit != "" {
				if d, err := providerCfg.UploadRateLimitDuration(); err != nil {
					fmt.Fprintf(os.Stderr, "cloud provider %s has invalid upload rate-limit configuration: %v`n", provider, err)
				} else {
					rateLimit = d
				}
			}

			timeout := 10 * time.Second
			if providerCfg.Timeout != "" {
				if d, err := providerCfg.TimeoutDuration(); err != nil {
					fmt.Fprintf(os.Stderr, "cloud provider %s has invalid timeout configuration: %v`n", provider, err)
				} else {
					timeout = d
				}
			}

			cacheTTL := 10 * time.Minute
			if providerCfg.CacheTTL != "" {
				if d, err := providerCfg.CacheTTLDuration(); err != nil {
					fmt.Fprintf(os.Stderr, "cloud provider %s has invalid cache-ttl configuration: %v`n", provider, err)
				} else {
					cacheTTL = d
				}
			}

			var (
				client riskanalysis.CloudClient
				err    error
			)
			switch provider {
			case "virustotal":
				client, err = riskanalysis.NewVirusTotalClient(riskanalysis.VirusTotalConfig{
					APIKey:              apiKey,
					BaseURL:             baseURL,
					ProxyURL:            proxyURL,
					Timeout:             timeout,
					RateLimit:           rateLimit,
					CacheTTL:            cacheTTL,
					TokenBucketCapacity: 4,
					TokenBucketWindow:   time.Minute,
				})
			case "hybrid_analysis":
				client, err = riskanalysis.NewHybridAnalysisClient(riskanalysis.HybridAnalysisConfig{
					APIKey:    apiKey,
					BaseURL:   baseURL,
					ProxyURL:  proxyURL,
					Timeout:   timeout,
					RateLimit: rateLimit,
					CacheTTL:  cacheTTL,
				})
			case "malwarebazaar":
				client, err = riskanalysis.NewMalwareBazaarClient(riskanalysis.MalwareBazaarConfig{
					APIKey:    apiKey,
					BaseURL:   baseURL,
					ProxyURL:  proxyURL,
					Timeout:   timeout,
					RateLimit: rateLimit,
					CacheTTL:  cacheTTL,
				})
			case "otx":
				client, err = riskanalysis.NewOTXClient(riskanalysis.OTXConfig{
					APIKey:    apiKey,
					BaseURL:   baseURL,
					ProxyURL:  proxyURL,
					Timeout:   timeout,
					RateLimit: rateLimit,
					CacheTTL:  cacheTTL,
				})
			case "triage":
				client, err = riskanalysis.NewTriageClient(riskanalysis.TriageConfig{
					APIKey:    apiKey,
					BaseURL:   baseURL,
					ProxyURL:  proxyURL,
					Timeout:   timeout,
					RateLimit: rateLimit,
					CacheTTL:  cacheTTL,
				})
			default:
				continue
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to initialize cloud provider %s: %v`n", provider, err)
				continue
			}
			clients = append(clients, riskanalysis.CloudProviderClient{Name: provider, Client: client})
		}

		cloudClient = &riskanalysis.MultiCloudClient{
			Providers:    clients,
			UploadPolicy: uploadPolicy,
		}
	}

	policy, policyPath, policyErr := riskanalysis.LoadWhitelistPolicy()
	if policyErr != nil {
		if policyPath != "" {
			fmt.Fprintf(os.Stderr, "\u52a0\u8f7d\u767d\u540d\u5355\u7b56\u7565\u5931\u8d25\uff08%s\uff09: %v\n", policyPath, policyErr)
		} else {
			fmt.Fprintf(os.Stderr, "\u52a0\u8f7d\u767d\u540d\u5355\u7b56\u7565\u5931\u8d25: %v\n", policyErr)
		}
		defaultPolicy := riskanalysis.DefaultWhitelistPolicy()
		policy = &defaultPolicy
	}
	_, projectWhitelistErr := applyProjectWhitelistPolicy(policy)
	if projectWhitelistErr != nil {
		fmt.Fprintf(os.Stderr, "risk analyze: project whitelist setup failed: %v\n", projectWhitelistErr)
	}
	hashRepo, hashRepoErr := riskanalysis.NewAuthorityHashRepo(policy)
	if hashRepoErr != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize authority hash repository: %v`n", hashRepoErr)
	}
	whitelistEngine := riskanalysis.NewDefaultWhitelistEngine(policy, hashRepo, nil)

	records, err := resolveRiskScanRecords(opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	progress := newRiskTerminalProgress(os.Stderr)
	defer progress.Done()

	analyzer := riskanalysis.Analyzer{
		Local:                    localMatcher,
		Cloud:                    cloudClient,
		Whitelist:                whitelistEngine,
		LocalWeight:              opts.LocalWeight,
		CloudWeight:              opts.CloudWeight,
		FastTimeout:              2 * time.Second,
		SmartTimeout:             10 * time.Second,
		DeepTimeout:              15 * time.Minute,
		CloudUploadEnabled:       opts.CloudUpload,
		CloudUploadConcurrency:   opts.CloudUploadConcurrency,
		CloudUploadWait:          opts.CloudUploadWait,
		CloudUploadSubmitTimeout: opts.CloudUploadSubmitTO,
		CloudUploadPollInterval:  opts.CloudUploadPollEvery,
		CloudUploadMaxSize:       opts.CloudUploadMaxSize,
		AnalysisMaxDuration:      opts.AnalysisMaxDuration,
		OnDiagnostic: func(message string) {
			progress.PrintLine(fmt.Sprintf("risk analyze: %s", message))
		},
		OnProgress: func(event riskanalysis.ProgressEvent) {
			progress.Update(event.Index, event.Total, event.Stage)
		},
	}

	ctx := context.Background()
	results, err := analyzer.Analyze(ctx, records, mode)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if opts.ExcelPath != "" {
		if err := writeRiskExcel(opts.ExcelPath, results); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stdout, opts.ExcelPath)
		return
	}

	if opts.JSONPath != "" {
		file, err := os.Create(opts.JSONPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer func() { _ = file.Close() }()

		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(results); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stdout, opts.JSONPath)
		return
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(results); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func resolveRiskScanRecords(opts riskOptions) ([]riskanalysis.ScanRecord, error) {
	if path := strings.TrimSpace(opts.InputPath); path != "" {
		return riskanalysis.LoadScanRecords(path)
	}

	if path := strings.TrimSpace(opts.FilePath); path != "" {
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if info.IsDir() {
			return nil, fmt.Errorf("invalid value: %s", path)
		}
		results, err := filescan.Scan(context.Background(), filescan.FileScanParams{
			Mode:       filescan.ScanModePath,
			Path:       path,
			MaxTargets: 1,
		})
		if err != nil {
			return nil, err
		}
		records := fileScanResultsToRiskRecords(results)
		if len(records) == 0 {
			return nil, fmt.Errorf("invalid value: %s", path)
		}
		return records, nil
	}

	if path := strings.TrimSpace(opts.DirPath); path != "" {
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("invalid value: %s", path)
		}
		results, err := filescan.Scan(context.Background(), filescan.FileScanParams{
			Mode: filescan.ScanModePath,
			Path: path,
		})
		if err != nil {
			return nil, err
		}
		records := fileScanResultsToRiskRecords(results)
		if len(records) == 0 {
			return nil, fmt.Errorf("invalid value: %s", path)
		}
		return records, nil
	}

	processName := strings.TrimSpace(opts.ProcessName)
	if opts.ProcessPID > 0 || processName != "" {
		params := processscan.ProcessScanParams{}
		if opts.ProcessPID > 0 {
			params.PIDs = []int{opts.ProcessPID}
		}
		if processName != "" {
			params.Name = &processName
		}
		results, err := processscan.Scan(context.Background(), params)
		if err != nil {
			return nil, err
		}
		records := processScanResultsToRiskRecords(results, opts.ProcessMemory, opts.MemoryMaxBytes)
		if len(records) == 0 {
			return nil, fmt.Errorf("invalid argument")
		}
		return records, nil
	}

	return nil, fmt.Errorf("invalid argument")
}

func fileScanResultsToRiskRecords(results []filescan.FileScanResult) []riskanalysis.ScanRecord {
	records := make([]riskanalysis.ScanRecord, 0, len(results))
	for _, result := range results {
		raw := map[string]any{
			"target_type": riskanalysis.TargetTypeFile,
		}

		if result.Hostname != nil && strings.TrimSpace(*result.Hostname) != "" {
			raw["hostname"] = strings.TrimSpace(*result.Hostname)
		}
		if result.BasicInfo != nil {
			if result.BasicInfo.FilePath != nil && strings.TrimSpace(*result.BasicInfo.FilePath) != "" {
				raw["target_path"] = strings.TrimSpace(*result.BasicInfo.FilePath)
			}
			if result.BasicInfo.FileSizeBytes != nil {
				raw["file_size"] = *result.BasicInfo.FileSizeBytes
			}
		}
		if result.Signature != nil && result.Signature.SignatureValid != nil {
			raw["signature_valid"] = *result.Signature.SignatureValid
		}
		if result.Signature != nil && result.Signature.SignerSubject != nil && strings.TrimSpace(*result.Signature.SignerSubject) != "" {
			raw["signer_subject"] = strings.TrimSpace(*result.Signature.SignerSubject)
		}
		if result.Signature != nil && result.Signature.CertificateThumbprint != nil && strings.TrimSpace(*result.Signature.CertificateThumbprint) != "" {
			raw["certificate_thumbprint"] = strings.TrimSpace(*result.Signature.CertificateThumbprint)
		}
		if result.BinaryInfo != nil && result.BinaryInfo.VersionInfo != nil && result.BinaryInfo.VersionInfo.FileDescription != nil && strings.TrimSpace(*result.BinaryInfo.VersionInfo.FileDescription) != "" {
			raw["product_name"] = strings.TrimSpace(*result.BinaryInfo.VersionInfo.FileDescription)
		}

		hashes := map[string]any{}
		if result.Hashes != nil && result.Hashes.Sha256 != nil && strings.TrimSpace(*result.Hashes.Sha256) != "" {
			hashes["sha256"] = strings.TrimSpace(*result.Hashes.Sha256)
		}
		if len(hashes) > 0 {
			raw["hashes"] = hashes
		}

		_, hasPath := raw["target_path"]
		if !hasPath && len(hashes) == 0 {
			continue
		}
		records = append(records, riskanalysis.ScanRecord{Raw: raw})
	}
	return records
}

func processScanResultsToRiskRecords(results []processscan.ProcessInfo, includeMemory bool, memoryMaxBytes int) []riskanalysis.ScanRecord {
	capacity := len(results)
	if includeMemory {
		capacity = capacity * 2
	}

	type processCtx struct {
		name string
		path string
	}
	processByPID := make(map[int]processCtx, len(results))
	for _, result := range results {
		if result.PID == nil {
			continue
		}
		ctx := processCtx{}
		if result.Name != nil {
			ctx.name = strings.TrimSpace(*result.Name)
		}
		if result.Path != nil {
			ctx.path = strings.TrimSpace(*result.Path)
		}
		processByPID[*result.PID] = ctx
	}

	records := make([]riskanalysis.ScanRecord, 0, capacity)
	for _, result := range results {
		raw := map[string]any{
			"target_type": riskanalysis.TargetTypeProcess,
		}
		if result.Hostname != nil && strings.TrimSpace(*result.Hostname) != "" {
			raw["hostname"] = strings.TrimSpace(*result.Hostname)
		}
		if result.PID != nil {
			raw["pid"] = *result.PID
		}
		if result.Path != nil && strings.TrimSpace(*result.Path) != "" {
			raw["target_path"] = strings.TrimSpace(*result.Path)
		}
		if result.Size != nil {
			raw["file_size"] = *result.Size
		}
		if result.Name != nil && strings.TrimSpace(*result.Name) != "" {
			raw["process_name"] = strings.TrimSpace(*result.Name)
		}
		if result.StartArgs != nil && strings.TrimSpace(*result.StartArgs) != "" {
			raw["start_args"] = strings.TrimSpace(*result.StartArgs)
		}
		if result.PPID != nil {
			raw["ppid"] = *result.PPID
			if parent, ok := processByPID[*result.PPID]; ok {
				if parent.name != "" {
					raw["parent_name"] = parent.name
				}
				if parent.path != "" {
					raw["parent_path"] = parent.path
				}
			}
		}

		hashes := map[string]any{}
		if result.Md5 != nil && strings.TrimSpace(*result.Md5) != "" {
			hashes["md5"] = strings.TrimSpace(*result.Md5)
		}
		if len(hashes) > 0 {
			raw["hashes"] = hashes
		}

		_, hasPath := raw["target_path"]
		if hasPath || len(hashes) > 0 {
			records = append(records, riskanalysis.ScanRecord{Raw: raw})
		}
		if !includeMemory {
			continue
		}
		memoryRaw := map[string]any{
			"target_type": riskanalysis.TargetTypeProcessMemory,
		}
		if host, ok := raw["hostname"]; ok {
			memoryRaw["hostname"] = host
		}
		if pid, ok := raw["pid"]; ok {
			memoryRaw["pid"] = pid
		}
		if targetPath, ok := raw["target_path"]; ok {
			memoryRaw["target_path"] = targetPath
		}
		if result.Name != nil && strings.TrimSpace(*result.Name) != "" {
			memoryRaw["process_name"] = strings.TrimSpace(*result.Name)
		}

		pid, ok := memoryRaw["pid"].(int)
		if !ok || pid <= 0 {
			memoryRaw["_memory_error"] = "missing PID, cannot collect process memory"
			records = append(records, riskanalysis.ScanRecord{Raw: memoryRaw})
			continue
		}

		payload, err := riskanalysis.CaptureProcessMemory(pid, memoryMaxBytes)
		if err != nil {
			memoryRaw["_memory_error"] = err.Error()
		} else if len(payload) == 0 {
			memoryRaw["_memory_error"] = "message"
		} else {
			memoryRaw["_memory_bytes"] = payload
			memoryRaw["_memory_size"] = len(payload)
		}
		records = append(records, riskanalysis.ScanRecord{Raw: memoryRaw})
	}
	return records
}

func defaultRulesPath() string {
	exe, err := os.Executable()
	if err != nil {
		exe = ""
	}
	if exe != "" {
		exeDir := filepath.Dir(exe)
		candidates := []string{
			filepath.Join(exeDir, "rules", "yaraRules"),
			filepath.Join(exeDir, "rules"),
		}
		for _, candidate := range candidates {
			info, err := os.Stat(candidate)
			if err == nil && info.IsDir() {
				return candidate
			}
		}
	}

	if embeddedPath, err := ensureEmbeddedRulesDir(); err == nil && strings.TrimSpace(embeddedPath) != "" {
		return embeddedPath
	}

	return ""
}

func providerEnvFallback(provider string) string {
	switch provider {
	case "virustotal":
		if val := os.Getenv("VT_API_KEY"); val != "" {
			return val
		}
	case "hybrid_analysis":
		if val := os.Getenv("HA_API_KEY"); val != "" {
			return val
		}
		if val := os.Getenv("HYBRID_ANALYSIS_API_KEY"); val != "" {
			return val
		}
	case "malwarebazaar":
		if val := os.Getenv("MB_API_KEY"); val != "" {
			return val
		}
		if val := os.Getenv("MALWAREBAZAAR_API_KEY"); val != "" {
			return val
		}
	case "otx":
		if val := os.Getenv("OTX_API_KEY"); val != "" {
			return val
		}
	case "triage":
		if val := os.Getenv("TRIAGE_API_KEY"); val != "" {
			return val
		}
	}
	return ""
}

func providerConfigFromFile(cfg *riskanalysis.CloudConfigFile, provider string) riskanalysis.CloudProviderConfig {
	if cfg == nil {
		return riskanalysis.CloudProviderConfig{}
	}
	normalized := riskanalysis.NormalizeProvider(provider)
	if normalized == "" {
		normalized = provider
	}
	if len(cfg.Providers) > 0 {
		for key, val := range cfg.Providers {
			if riskanalysis.NormalizeProvider(key) == normalized {
				return val
			}
		}
	}
	if riskanalysis.NormalizeProvider(cfg.Provider) == normalized || (cfg.Provider == "" && normalized == "virustotal" && len(cfg.Providers) == 0) {
		return riskanalysis.CloudProviderConfig{
			APIKey:          cfg.APIKey,
			BaseURL:         cfg.BaseURL,
			ProxyURL:        cfg.ProxyURL,
			RateLimit:       cfg.RateLimit,
			Timeout:         cfg.Timeout,
			CacheTTL:        cfg.CacheTTL,
			UploadEnabled:   nil,
			UploadRateLimit: "",
		}
	}
	return riskanalysis.CloudProviderConfig{}
}

type fileScanOptions struct {
	Mode       filescan.ScanMode
	Path       string
	ExcelPath  string
	MaxTargets int
	ShowHelp   bool
}

func parseFileScanFlags(args []string) (fileScanOptions, error) {
	fs := flag.NewFlagSet("file-scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, "  c-eyes file scan -mode [full|path|smart] [-path <target>] [-excel out.xlsx]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Options:")
		fs.PrintDefaults()
	}

	var opts fileScanOptions
	var mode string
	var maxTargets int
	fs.StringVar(&mode, "mode", "smart", "Scan mode: full, path, or smart")
	fs.StringVar(&opts.Path, "path", "", "Target file or directory path when mode=path")
	fs.StringVar(&opts.ExcelPath, "excel", "", "Export Excel file path (.xlsx)")
	fs.IntVar(&maxTargets, "maxTargets", 0, "Maximum targets to scan (0 means unlimited)")

	for _, arg := range args {
		if arg == "-h" || arg == "--help" {
			opts.ShowHelp = true
			fs.Usage()
			return opts, nil
		}
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			opts.ShowHelp = true
			return opts, nil
		}
		return opts, err
	}
	if opts.ShowHelp {
		fs.Usage()
		return opts, nil
	}

	mode = strings.ToLower(mode)
	switch filescan.ScanMode(mode) {
	case filescan.ScanModeFull, filescan.ScanModePath, filescan.ScanModeSmart:
		opts.Mode = filescan.ScanMode(mode)
	default:
		return opts, fmt.Errorf("invalid mode: %s", mode)
	}

	if opts.Mode == filescan.ScanModePath && opts.Path == "" {
		return opts, fmt.Errorf("mode=path requires -path <target>")
	}

	opts.MaxTargets = maxTargets
	return opts, nil
}
func fileScan(args []string) {
	opts, err := parseFileScanFlags(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if opts.ShowHelp {
		return
	}

	progress := newTerminalProgress(os.Stderr, "file scan")
	defer progress.Done()

	params := filescan.FileScanParams{
		Mode:       opts.Mode,
		Path:       opts.Path,
		MaxTargets: opts.MaxTargets,
		Progress:   progress.Update,
	}

	ctx := context.Background()
	results, err := filescan.Scan(ctx, params)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if opts.ExcelPath != "" {
		if err := writeFileExcel(opts.ExcelPath, results); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stdout, opts.ExcelPath)
		return
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(results); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
