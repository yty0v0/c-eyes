package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"unicode"

	"edrsystem/internal/webapplicationscan"
)

type webApplicationScanOptions struct {
	Params       webapplicationscan.WebApplicationScanParams
	OutputFormat string
	ExcelPath    string
	ShowHelp     bool
}

func parseWebApplicationScanFlags(args []string) (webApplicationScanOptions, error) {
	fs := flag.NewFlagSet("web-application-scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "用法：")
		fmt.Fprintln(os.Stderr, "  c-eyes web-application-scan [参数] [-output json|excel] [-excel out.xlsx]")
		fmt.Fprintln(os.Stderr, "\n参数：")
		fs.PrintDefaults()
	}

	var opts webApplicationScanOptions
	var hostname, ip, appName, rootPath, webRoot, domainName string
	var groups intSliceFlag
	var version stringSliceFlag
	var serverName stringSliceFlag
	output := outputModeFlag{value: "json"}

	fs.Var(&groups, "groups", "按业务组 ID 过滤（逗号分隔）")
	fs.StringVar(&hostname, "hostname", "", "按主机名模糊过滤")
	fs.StringVar(&ip, "ip", "", "按主机 IP 模糊过滤")
	fs.Var(&version, "version", "按应用版本过滤（逗号分隔）")
	fs.StringVar(&appName, "appName", "", "按应用名称模糊过滤")
	fs.StringVar(&rootPath, "rootPath", "", "按根路径模糊过滤")
	fs.StringVar(&webRoot, "webRoot", "", "按站点根路径模糊过滤")
	fs.Var(&serverName, "serverName", "按服务类型过滤（逗号分隔，如 nginx,apache,tomcat）")
	fs.StringVar(&domainName, "domainName", "", "按域名模糊过滤")
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
	if version.set && len(version.values) == 0 {
		return opts, fmt.Errorf("参数不合法: version 不能为空")
	}
	if serverName.set && len(serverName.values) == 0 {
		return opts, fmt.Errorf("参数不合法: serverName 不能为空")
	}
	for _, item := range version.values {
		if err := validateArrayValue("version", item); err != nil {
			return opts, err
		}
	}
	for _, item := range serverName.values {
		if err := validateArrayValue("serverName", item); err != nil {
			return opts, err
		}
	}
	for key, value := range map[string]string{
		"hostname":   hostname,
		"ip":         ip,
		"appName":    appName,
		"rootPath":   rootPath,
		"webRoot":    webRoot,
		"domainName": domainName,
	} {
		if err := validateFuzzyValue(key, value); err != nil {
			return opts, err
		}
	}

	params := webapplicationscan.WebApplicationScanParams{}
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
	if version.set {
		params.Version = append(params.Version, version.values...)
	}
	if appName != "" {
		params.AppName = &appName
	}
	if rootPath != "" {
		params.RootPath = &rootPath
	}
	if webRoot != "" {
		params.WebRoot = &webRoot
	}
	if serverName.set {
		params.ServerName = append(params.ServerName, serverName.values...)
	}
	if domainName != "" {
		params.DomainName = &domainName
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

func validateArrayValue(name, value string) error {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return fmt.Errorf("参数不合法: %s 包含空值", name)
	}
	for _, r := range trimmed {
		if unicode.IsControl(r) {
			return fmt.Errorf("参数不合法: %s 含控制字符", name)
		}
	}
	return nil
}

func validateFuzzyValue(name, value string) error {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	for _, r := range trimmed {
		if unicode.IsControl(r) {
			return fmt.Errorf("参数不合法: %s 含控制字符", name)
		}
	}
	return nil
}

func webApplicationScan(args []string) {
	opts, err := parseWebApplicationScanFlags(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if opts.ShowHelp {
		return
	}

	progress := newTerminalProgress(os.Stderr, "web application scan")
	defer progress.Done()
	opts.Params.Progress = progress.Update

	result, err := webapplicationscan.Scan(context.Background(), opts.Params)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if opts.OutputFormat == "excel" {
		if err := writeWebApplicationScanExcel(opts.ExcelPath, result.Rows); err != nil {
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
