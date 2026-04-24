package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"edrsystem/internal/databasescan"
)

type databaseScanOptions struct {
	Params       databasescan.DatabaseScanParams
	OutputFormat string
	ExcelPath    string
	ShowHelp     bool
}

func parseDatabaseScanFlags(args []string) (databaseScanOptions, error) {
	fs := flag.NewFlagSet("database-scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "用法:")
		fmt.Fprintln(os.Stderr, "  c-eyes database-scan [参数] [-output json|excel] [-excel out.xlsx]")
		fmt.Fprintln(os.Stderr, "\n参数:")
		fs.PrintDefaults()
	}

	var opts databaseScanOptions
	var hostname, ip, name, confPath, logPath, dataDir string
	var groups intSliceFlag
	var versions stringSliceFlag
	var port optionalInt
	output := outputModeFlag{value: "json"}

	fs.Var(&groups, "groups", "按组 ID 过滤，逗号分隔")
	fs.StringVar(&hostname, "hostname", "", "按主机名模糊过滤")
	fs.StringVar(&ip, "ip", "", "按 IP 模糊过滤")
	fs.StringVar(&name, "name", "", "按数据库类型过滤")
	fs.Var(&versions, "versions", "按数据库版本过滤，逗号分隔")
	fs.Var(&port, "port", "按监听端口过滤")
	fs.StringVar(&confPath, "confPath", "", "按配置路径模糊过滤")
	fs.StringVar(&logPath, "logPath", "", "按日志路径模糊过滤")
	fs.StringVar(&dataDir, "dataDir", "", "按数据目录模糊过滤")
	fs.Var(&output, "output", "输出格式：json 或 excel")
	fs.StringVar(&opts.ExcelPath, "excel", "", "导出 Excel 文件路径（.xlsx）")

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

	params := databasescan.DatabaseScanParams{}
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
		params.Versions = append(params.Versions, versions.values...)
	}
	if port.set {
		params.Port = &port.value
	}
	if confPath != "" {
		params.ConfPath = &confPath
	}
	if logPath != "" {
		params.LogPath = &logPath
	}
	if dataDir != "" {
		params.DataDir = &dataDir
	}

	if strings.TrimSpace(opts.ExcelPath) != "" && !output.set {
		output.value = "excel"
	}

	outputMode := strings.ToLower(strings.TrimSpace(output.value))
	switch outputMode {
	case "json", "excel":
		opts.OutputFormat = outputMode
	default:
		return opts, fmt.Errorf("output 参数无效: %s", output.value)
	}
	if opts.OutputFormat == "excel" && strings.TrimSpace(opts.ExcelPath) == "" {
		return opts, fmt.Errorf("使用 output=excel 时必须提供 -excel 文件路径")
	}

	opts.Params = params
	return opts, nil
}

func databaseScan(args []string) {
	opts, err := parseDatabaseScanFlags(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if opts.ShowHelp {
		return
	}

	progress := newTerminalProgress(os.Stderr, "database scan")
	defer progress.Done()
	opts.Params.Progress = progress.Update

	results, err := databasescan.Scan(context.Background(), opts.Params)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if opts.OutputFormat == "excel" {
		if err := writeDatabaseScanExcel(opts.ExcelPath, results.Rows); err != nil {
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
