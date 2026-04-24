package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"edrsystem/internal/jarpackagescan"
)

type jarPackageScanOptions struct {
	Params       jarpackagescan.JarPackageScanParams
	OutputFormat string
	ExcelPath    string
	ShowHelp     bool
}

func parseJarPackageScanFlags(args []string) (jarPackageScanOptions, error) {
	fs := flag.NewFlagSet("jar-package-scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, "  c-eyes jar-package-scan [flags] [-output json|excel] [-excel out.xlsx]")
		fmt.Fprintln(os.Stderr, "\nFlags:")
		fs.PrintDefaults()
	}

	var opts jarPackageScanOptions
	var hostname, ip, name, path string
	var groups intSliceFlag
	var versions stringSliceFlag
	var types intSliceFlag
	var executable boolSliceFlag
	output := outputModeFlag{value: "json"}

	fs.Var(&groups, "groups", "Filter by business group IDs (comma-separated)")
	fs.StringVar(&hostname, "hostname", "", "Filter by hostname (fuzzy match)")
	fs.StringVar(&ip, "ip", "", "Filter by host IP (fuzzy match)")
	fs.StringVar(&name, "name", "", "Filter by jar package name (fuzzy match)")
	fs.Var(&versions, "version", "Filter by jar package versions (comma-separated)")
	fs.Var(&types, "type", "Filter by package type values (1,2,3,8; comma-separated)")
	fs.Var(&executable, "executable", "Filter by executable flag (true/false, comma-separated)")
	fs.StringVar(&path, "path", "", "Filter by absolute path (fuzzy match)")
	fs.Var(&output, "output", "Output format (json or excel)")
	fs.StringVar(&opts.ExcelPath, "excel", "", "Excel output file path (.xlsx)")

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

	if groups.set && len(groups.values) == 0 {
		return opts, fmt.Errorf("invalid argument: groups cannot be empty")
	}
	if versions.set && len(versions.values) == 0 {
		return opts, fmt.Errorf("invalid argument: version cannot be empty")
	}
	if types.set && len(types.values) == 0 {
		return opts, fmt.Errorf("invalid argument: type cannot be empty")
	}
	if executable.set && len(executable.values) == 0 {
		return opts, fmt.Errorf("invalid argument: executable cannot be empty")
	}

	for _, item := range versions.values {
		if err := validateArrayValue("version", item); err != nil {
			return opts, err
		}
	}
	for _, item := range types.values {
		if err := validateJarPackageTypeValue(item); err != nil {
			return opts, err
		}
	}
	for key, value := range map[string]string{
		"hostname": hostname,
		"ip":       ip,
		"name":     name,
		"path":     path,
	} {
		if err := validateFuzzyValue(key, value); err != nil {
			return opts, err
		}
	}

	params := jarpackagescan.JarPackageScanParams{}
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
	if versions.set {
		params.Version = append(params.Version, versions.values...)
	}
	if types.set {
		params.Type = append(params.Type, types.values...)
	}
	if executable.set {
		params.Executable = append(params.Executable, executable.values...)
	}
	if path != "" {
		params.Path = &path
	}

	if strings.TrimSpace(opts.ExcelPath) != "" && !output.set {
		output.value = "excel"
	}

	outputMode := strings.ToLower(strings.TrimSpace(output.value))
	switch outputMode {
	case "json", "excel":
		opts.OutputFormat = outputMode
	default:
		return opts, fmt.Errorf("invalid value: %s", output.value)
	}
	if opts.OutputFormat == "excel" && strings.TrimSpace(opts.ExcelPath) == "" {
		return opts, fmt.Errorf("invalid argument")
	}

	opts.Params = params
	return opts, nil
}

func validateJarPackageTypeValue(v int) error {
	switch v {
	case 1, 2, 3, 8:
		return nil
	default:
		return fmt.Errorf("invalid value: type %d is not in [1,2,3,8]", v)
	}
}

func jarPackageScan(args []string) {
	opts, err := parseJarPackageScanFlags(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if opts.ShowHelp {
		return
	}

	progress := newTerminalProgress(os.Stderr, "jar package scan")
	defer progress.Done()
	opts.Params.Progress = progress.Update

	result, err := jarpackagescan.Scan(context.Background(), opts.Params)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if opts.OutputFormat == "excel" {
		if err := writeJarPackageScanExcel(opts.ExcelPath, result.Rows); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stdout, opts.ExcelPath)
		return
	}

	if err := jarpackagescan.WriteJSON(os.Stdout, result); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
