package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"edrsystem/internal/websitescan"
)

type webSiteScanOptions struct {
	Params       websitescan.WebSiteScanParams
	OutputFormat string
	ExcelPath    string
	ShowHelp     bool
}

func parseWebSiteScanFlags(args []string) (webSiteScanOptions, error) {
	fs := flag.NewFlagSet("web-site-scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "用法:")
		fmt.Fprintln(os.Stderr, "  c-eyes web-site-scan [参数] [-output json|excel] [-excel out.xlsx]")
		fmt.Fprintln(os.Stderr, "\n参数:")
		fs.PrintDefaults()
	}

	var opts webSiteScanOptions
	var hostname, ip, proto, rootPath string
	var groups intSliceFlag
	var types stringSliceFlag
	var port optionalInt
	output := outputModeFlag{value: "json"}

	fs.Var(&groups, "groups", "按业务组 ID 过滤（逗号分隔）")
	fs.StringVar(&hostname, "hostname", "", "按主机名模糊过滤")
	fs.StringVar(&ip, "ip", "", "按主机 IP 模糊过滤")
	fs.Var(&port, "port", "按站点端口过滤")
	fs.StringVar(&proto, "proto", "", "按站点协议精确过滤（如 http/https）")
	fs.Var(&types, "type", "按站点类型精确过滤（逗号分隔，如 iis,nginx,tomcat）")
	fs.StringVar(&rootPath, "rootPath", "", "按站点路径模糊过滤")
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
	for _, item := range types.values {
		if err := validateArrayValue("type", item); err != nil {
			return opts, err
		}
	}
	for key, value := range map[string]string{
		"hostname": hostname,
		"ip":       ip,
		"rootPath": rootPath,
	} {
		if err := validateFuzzyValue(key, value); err != nil {
			return opts, err
		}
	}
	if proto != "" {
		p := strings.ToLower(strings.TrimSpace(proto))
		if p != "http" && p != "https" {
			return opts, fmt.Errorf("参数不合法: proto 仅支持 http 或 https")
		}
	}

	params := websitescan.WebSiteScanParams{}
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
	if port.set {
		params.Port = &port.value
	}
	if proto != "" {
		proto = strings.ToLower(strings.TrimSpace(proto))
		params.Proto = &proto
	}
	if types.set {
		params.Type = append(params.Type, types.values...)
	}
	if rootPath != "" {
		params.RootPath = &rootPath
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

func webSiteScan(args []string) {
	opts, err := parseWebSiteScanFlags(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if opts.ShowHelp {
		return
	}

	progress := newTerminalProgress(os.Stderr, "web site scan")
	defer progress.Done()
	opts.Params.Progress = progress.Update

	result, err := websitescan.Scan(context.Background(), opts.Params)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if opts.OutputFormat == "excel" {
		if err := writeWebSiteScanExcel(opts.ExcelPath, result.Rows); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stdout, opts.ExcelPath)
		return
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
