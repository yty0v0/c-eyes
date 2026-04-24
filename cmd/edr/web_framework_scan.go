package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"edrsystem/internal/webframescan"
)

type webFrameworkScanOptions struct {
	Params       webframescan.WebFrameScanParams
	OutputFormat string
	ExcelPath    string
	ShowHelp     bool
}

func parseWebFrameworkScanFlags(args []string) (webFrameworkScanOptions, error) {
	fs := flag.NewFlagSet("web-framework-scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "用法:")
		fmt.Fprintln(os.Stderr, "  c-eyes web-framework-scan [参数] [-output json|excel] [-excel out.xlsx]")
		fmt.Fprintln(os.Stderr, "\n参数:")
		fs.PrintDefaults()
	}

	var opts webFrameworkScanOptions
	var hostname, ip, name, version string
	var groups intSliceFlag
	var types stringSliceFlag
	var serverNames stringSliceFlag
	output := outputModeFlag{value: "json"}

	fs.Var(&groups, "groups", "按业务组 ID 过滤（逗号分隔）")
	fs.StringVar(&hostname, "hostname", "", "按主机名模糊过滤")
	fs.StringVar(&ip, "ip", "", "按主机 IP 模糊过滤")
	fs.StringVar(&name, "name", "", "按 Web 框架名称模糊过滤")
	fs.StringVar(&version, "version", "", "按 Web 框架版本过滤")
	fs.Var(&types, "type", "按框架语言过滤（逗号分隔）")
	fs.Var(&serverNames, "serverName", "按服务类型过滤（逗号分隔）")
	fs.Var(&output, "output", "输出格式（json 或 excel）")
	fs.StringVar(&opts.ExcelPath, "excel", "", "Excel 输出文件路径（.xlsx）")

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
		return opts, fmt.Errorf("参数不合法: groups 不能为空")
	}
	if types.set && len(types.values) == 0 {
		return opts, fmt.Errorf("参数不合法: type 不能为空")
	}
	if serverNames.set && len(serverNames.values) == 0 {
		return opts, fmt.Errorf("参数不合法: serverName 不能为空")
	}
	for _, item := range types.values {
		if err := validateArrayValue("type", item); err != nil {
			return opts, err
		}
	}
	for _, item := range serverNames.values {
		if err := validateArrayValue("serverName", item); err != nil {
			return opts, err
		}
	}
	for key, value := range map[string]string{
		"hostname": hostname,
		"ip":       ip,
		"name":     name,
		"version":  version,
	} {
		if err := validateFuzzyValue(key, value); err != nil {
			return opts, err
		}
	}

	params := webframescan.WebFrameScanParams{}
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
	if version != "" {
		params.Version = &version
	}
	if types.set {
		params.Type = append(params.Type, types.values...)
	}
	if serverNames.set {
		params.ServerName = append(params.ServerName, serverNames.values...)
	}

	if strings.TrimSpace(opts.ExcelPath) != "" && !output.set {
		output.value = "excel"
	}

	outputMode := strings.ToLower(strings.TrimSpace(output.value))
	switch outputMode {
	case "json", "excel":
		opts.OutputFormat = outputMode
	default:
		return opts, fmt.Errorf("参数不合法: %s", output.value)
	}
	if opts.OutputFormat == "excel" && strings.TrimSpace(opts.ExcelPath) == "" {
		return opts, fmt.Errorf("使用 output=excel 时必须指定 -excel 输出路径")
	}

	opts.Params = params
	return opts, nil
}

func webFrameworkScan(args []string) {
	opts, err := parseWebFrameworkScanFlags(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if opts.ShowHelp {
		return
	}

	progress := newTerminalProgress(os.Stderr, "web framework scan")
	defer progress.Done()
	opts.Params.Progress = progress.Update

	result, err := webframescan.Scan(context.Background(), opts.Params)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if opts.OutputFormat == "excel" {
		if err := writeWebFrameworkScanExcel(opts.ExcelPath, result.Rows); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stdout, opts.ExcelPath)
		return
	}

	if err := webframescan.WriteJSON(os.Stdout, result); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
