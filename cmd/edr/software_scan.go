package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"edrsystem/internal/softwarescan"
)

type softwareScanOptions struct {
	Params       softwarescan.SoftwareScanParams
	OutputFormat string
	ExcelPath    string
	ShowHelp     bool
}

func parseSoftwareScanFlags(args []string) (softwareScanOptions, error) {
	fs := flag.NewFlagSet("software-scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, "  c-eyes software-scan [flags] [-output json|excel] [-excel out.xlsx]")
		fmt.Fprintln(os.Stderr, "\nFlags:")
		fs.PrintDefaults()
	}

	var opts softwareScanOptions
	var hostname, ip, name, binPath, configPath string
	var groups intSliceFlag
	var versions stringSliceFlag
	output := outputModeFlag{value: "json"}

	fs.Var(&groups, "groups", "Filter by business group IDs (comma-separated)")
	fs.StringVar(&hostname, "hostname", "", "Filter by hostname (fuzzy match)")
	fs.StringVar(&ip, "ip", "", "Filter by host IP (fuzzy match)")
	fs.StringVar(&name, "name", "", "Filter by software name (fuzzy match)")
	fs.Var(&versions, "version", "Filter by software versions (comma-separated)")
	fs.StringVar(&binPath, "binPath", "", "Filter by binary/install path (fuzzy match)")
	fs.StringVar(&configPath, "configPath", "", "Filter by config path (fuzzy match)")
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
	for _, item := range versions.values {
		if err := validateArrayValue("version", item); err != nil {
			return opts, err
		}
	}
	for key, value := range map[string]string{
		"hostname":   hostname,
		"ip":         ip,
		"name":       name,
		"binPath":    binPath,
		"configPath": configPath,
	} {
		if err := validateFuzzyValue(key, value); err != nil {
			return opts, err
		}
	}

	params := softwarescan.SoftwareScanParams{}
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
	if binPath != "" {
		params.BinPath = &binPath
	}
	if configPath != "" {
		params.ConfigPath = &configPath
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
