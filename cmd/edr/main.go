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
		fmt.Fprintln(os.Stderr, "闂傚倸鍊搁崐鎼佸磹閻戣姤鍊块柨鏇楀亾妞ゎ亜鍟村畷褰掝敋閸涱垰濮洪梻浣侯潒閸曞灚鐣剁紓浣插亾濠㈣泛澶囬崑鎾荤嵁閸喖濮庡┑鐐额嚋缁犳挸鐣?")
		fmt.Fprintln(os.Stderr, "  c-eyes process scan [flags]")
		fmt.Fprintln(os.Stderr, "\n闂傚倸鍊搁崐鎼佸磹妞嬪海鐭嗗〒姘ｅ亾妤犵偛顦甸弫鎾绘偐閸愯弓鐢婚梻渚€娼чˇ顐﹀疾濞戞艾顥氶柛锔诲幗閸犳劙鏌ｅΔ鈧悧鍡欑箔閹烘挻鍙?")
		fs.PrintDefaults()
	}

	var opts processScanOptions
	var hostname, ip, startTime, packageName, state, path, uname, gname, name, startArgs, tty, description string
	var versions, packageVersions stringSliceFlag
	var pids, types intSliceFlag
	var root optionalBool
	var installedByPm optionalBool

	fs.StringVar(&hostname, "hostname", "", "闂備礁婀遍…鍫ニ囬閿亾闂堟稓鐒哥€殿喚鏁诲畷顐﹀礋椤掆偓閳ь剚濞婂鍫曞煛娴ｇ懓顦╅梺?")
	fs.StringVar(&ip, "ip", "", "闂?IP 闂佸搫顦弲娑樏洪敃鍌氱")
	fs.StringVar(&startTime, "startTime", "", "闂傚倸鍊搁崐鎼佸磹妞嬪海鐭嗗ù锝夋交閼板潡姊洪鈧粔顕€鍩€椤掑﹦鐣电€规洖銈告俊椋庘偓锝庝簼閸犳ɑ銇勯姀锛勬创闁诡喗鐟╅幊鐘活敆閸屾稒鐦為梻鍌欒兌閹虫捇宕ョ€ｎ喗鍋╂い蹇撶墕缁€澶屸偓鍏夊亾闁逞屽墰閸掓帡宕奸悢椋庣獮闂佸綊鍋婇崢楣冨储椤忓懐绡€闁汇垽娼у瓭缂備胶绮敋妞ゎ剙锕、娆愭叏閹邦亞鐩庨梺鎸庣矊椤嘲鐣烽崼鏇炍╅柕蹇娾偓鎰佷紲闂傚倸鍊烽懗鍫曗€﹂崼銉ュ珘妞ゆ帒鍊搁崹婵嬫煟濡搫妫樻繛鎴炵懄閸庣喖鏌ㄥ┑鍡樺窛闁挎稒绮撻弻锝夋偐閸欏顦╅悷婊勬緲閸熸潙顕ｉ崘娴嬫瀻闁规壋鏅欑花璇差渻閵堝棙灏扮紒顔兼湰閹便劑宕掑锝嗘杸闂佹枼鏅涢崯顐﹀礉閸撲胶纾奸柣妯虹－濞插鈧鍠楅幐鎶藉箖椤忓牆鐒垫い鎺嗗亾閸楅亶鏌ｉ幋锝呅撻柍閿嬪笒闇夐柨婵嗘媼濞肩喖鏌嶈閸忔﹢宕戦幘缁樷拺缂佸顑欓崕鎰版煙缁嬫鐓煎┑锛勬暬瀹曠喖顢涘顒€鏁ら梻渚€娼ц噹闁逞屽墮鍗遍柛顐犲劜閳?RFC3339 闂?YYYY-MM-DD")
	fs.Var(&versions, "versions", "闂備礁婀遍…鍫ニ囧畷鍥ㄥ床婵☆垵鍋愰惌娆撴倵閿濆骸澧い锝呫偢閺岋繝宕奸銏犫拤缂備浇顕ч崯顐︹€﹂妸鈺佄ч煫鍥ㄦ礈椤︻噣姊绘笟鍥т簼妞ゃ劌鎳撻妵鎰板锤濡も偓缁€鍡涙煕閳╁啰鈯曟い?")
	fs.Var(&root, "root", "闂佸湱顭堥ˇ鏉课ｉ幖浣歌Е?root 闂佸搫顦崯鏉戭瀶閻戞ɑ浜ら柛銉ｅ妽婵垽鏌ㄥ☉妯荤窡rue/false闂?")
	fs.StringVar(&packageName, "packageName", "", "闂佸湱顭堥ˇ顖溾偓鍨耿瀹曘儱顓奸崼銏㈢暫濠?")
	fs.Var(&packageVersions, "packageVersions", "闂備礁婀遍…鍫ニ囬婧惧亾閸偓鑰块柟顔ㄥ洤閱囬柣鏂挎啞鐎氭娊鏌℃径鍡樻珔婵炶绠撻獮搴ㄥΧ婢跺娅栭悗鍏夊亾闁告洏鍔屾禍鐐繆閵堝倸浜鹃悷婊勬緲濞尖€崇暦濮樿泛骞㈡繛鎴炵懐閸?")
	fs.Var(&installedByPm, "installedByPm", "闂佸湱顭堥ˇ鏉课ｉ幖浣歌Е闁挎梻鍋撻弳鐘绘煕閺嵮勫櫧妞ゆ挻鎮傞幃鍫曞幢濡や胶褰滈柣搴ｆ嚀椤︽娊藟婵犲啯浜ら柛銉ｅ妽婵垽鏌ㄥ☉妯荤窡rue/false闂?")
	fs.Var(&pids, "pids", "闂?PID 闂佸搫顦弲娑樏洪敃鍌氱闁靛牆顦伴弲顒傗偓鍏夊亾闁告洏鍔屾禍鐐繆閵堝倸浜鹃悷婊勬緲濞尖€崇暦濮樿泛骞㈡繛鎴炵懐閸?")
	fs.StringVar(&state, "state", "", "闂佸湱顭堥ˇ宕囨崲濡偐鐭欓悗锝庡墮绗戦梺璇″厸濞村洨鎹㈤崘顭戠叆")
	fs.StringVar(&path, "path", "", "闂佸湱顭堥ˇ宕囨崲濡偐鐭欓悗锝庡幘閻斿懐鈧灚婢樼€氼垳鎹㈤崘顭戠叆")
	fs.StringVar(&uname, "uname", "", "闂備礁婀遍…鍫ニ囬柆宥呮瀬闁靛牆顦粻锝団偓鐟板婢ф宕愰幎钘夌骇闁宠桨鐒︽径鍕煙?")
	fs.StringVar(&gname, "gname", "", "闂佸湱顭堥ˇ杈╁垝瀹ュ瑙︾€广儱鐗忕粻鏍ㄧ節?")
	fs.StringVar(&name, "name", "", "闂備礁婀遍…鍫ニ囧畷鍥ㄥ床婵☆垵鍋愰惌娆撴倵閿濆簼绨奸柛濠冨▕瀵爼鍩℃担鐟邦槱闂?")
	fs.StringVar(&startArgs, "startArgs", "", "闂佸湱顭堥ˇ顖炲箚鎼淬劌绀夐柕濞垮劚濡﹢鏌℃担鐟邦€滅紒璇插暙椤?")
	fs.StringVar(&tty, "tty", "", "闂?TTY 闂佸搫顦弲娑樏洪敃鍌氱")
	fs.StringVar(&description, "description", "", "闂佸湱顭堥ˇ宕囨崲濡偐鐭欓悗锝庡亜娴煎酣寮堕埡鍌氼€滅紒璇插暙椤?")
	fs.Var(&types, "types", "闂備礁婀遍…鍫ニ囧畷鍥ㄥ床婵☆垵鍋愰惌娆撴倵閿濆骸澧叉い顐畵閺屾盯濡搁妷顔煎壍缂備浇顕ч崯顐︹€﹂妸鈺佄ч煫鍥ㄦ礈椤︻噣姊绘笟鍥т簼妞ゃ劌鎳撻妵鎰板锤濡も偓缁€鍡涙煕閳╁啰鈯曟い?")
	fs.StringVar(&opts.ExcelPath, "excel", "", "闁诲海鏁搁崢褔宕?Excel 闂佸搫鍊稿ú锝呪枎閵忋垺宕夋い鏍ㄦ皑缁愮偤鏌?xlsx闂?")

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
			return opts, fmt.Errorf("startTime 闂傚倸鍊搁崐鎼佸磹妞嬪海鐭嗗〒姘ｅ亾妤犵偞鐗犻、鏇㈡晝閳ь剟鎮块濮愪簻闁规澘鐖煎顕€鏌涚€ｎ亶妯€闁哄矉缍侀獮姗€宕樺顔兼暔婵犵數鍋為崹顖炲垂瑜版帗鐓ラ柕鍫濇缁诲棝鏌曢崼婵嗏偓鍛婄妤ｅ啯鈷戦柛娑橈工婵偓闂佺顑嗛幑鍥ь潖缂佹ɑ濯撮柧蹇曟嚀缁楋繝姊洪悷鐗堟喐妞ゎ厼鐗撳﹢浣逛繆閻愬樊鍎忛悗娑掓櫊瀹曟顭ㄩ崼鐔哄帗閻熸粍绮撳畷婊堟偄婵傚缍庡┑鐐叉▕娴滄粍瀵奸悩缁樼厱闁哄洢鍔屾禍婵囩箾閸絽鐓愮紒缁樼箓閳绘捇宕归鐣屼壕闂備浇妗ㄥù鍥敋瑜旈、? %w", err)
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
		fmt.Fprintln(os.Stderr, "闂傚倸鍊搁崐鎼佸磹閻戣姤鍊块柨鏇楀亾妞ゎ亜鍟村畷褰掝敋閸涱垰濮洪梻浣侯潒閸曞灚鐣剁紓浣插亾濠㈣泛澶囬崑鎾荤嵁閸喖濮庡┑鐐额嚋缁犳挸鐣?")
		fmt.Fprintln(os.Stderr, "  c-eyes account scan [闂傚倸鍊搁崐鎼佸磹妞嬪海鐭嗗〒姘ｅ亾妤犵偛顦甸弫鎾绘偐閸愯弓鐢婚梻渚€娼чˇ顐﹀疾濞戞艾顥氶柛锔诲幗閸犳劙鏌ｅΔ鈧悧鍡欑箔閹烘挻鍙忛悷娆忓閸欌偓闂?[-output json|excel] [-excel out.xlsx]")
		fmt.Fprintln(os.Stderr, "\n闂傚倸鍊搁崐鎼佸磹妞嬪海鐭嗗〒姘ｅ亾妤犵偛顦甸弫鎾绘偐閸愯弓鐢婚梻渚€娼чˇ顐﹀疾濞戞艾顥氶柛锔诲幗閸犳劙鏌ｅΔ鈧悧鍡欑箔閹烘挻鍙?")
		fs.PrintDefaults()
	}

	var opts accountScanOptions
	var hostname, ip, name, home, lastLoginFrom, lastLoginTo string
	output := outputModeFlag{value: "json"}
	var gid, uid string
	var groups, status intSliceFlag

	fs.Var(&groups, "groups", "闂備礁婀遍…鍫ニ囨潏鈺佸灊?ID 闂佸搫顦弲娑樏洪敃鍌氱闁靛牆顦伴弲顒傗偓鍏夊亾闁告洏鍔屾禍鐐繆閵堝倸浜鹃悷婊勬緲濞尖€崇暦濮樿泛骞㈡繛鎴炵懐閸?")
	fs.StringVar(&hostname, "hostname", "", "闂備礁婀遍…鍫ニ囬閿亾闂堟稓鐒哥€殿喚鏁诲畷顐﹀礋椤掆偓閳ь剚濞婂鍫曞煛娴ｇ懓顦╅梺?")
	fs.StringVar(&ip, "ip", "", "闂?IP 闂佸搫顦弲娑樏洪敃鍌氱")
	fs.Var(&status, "status", "闂佸湱顭堥ˇ铏緞閸曨垰鐭楀瀣绗戦梺璇″厸濞村洨鎹㈤崘顭戠叆闁靛牆绻掔粈澶愭⒑椤愶綆娈旂憸鏉挎健瀹曟岸宕卞☉娆樺悩")
	fs.StringVar(&name, "name", "", "闂備礁婀遍…鍫ニ囬柆宥呮瀬闁靛牆顦粻锝団偓鐟板婢ф宕愰幎钘夌骇闁宠桨鐒︽径鍕煙?")
	fs.StringVar(&home, "home", "", "闂?home 闂備胶鍎甸弲鈺呭窗閺嶎偆绀婄€广儱妫欐禍銈夋煕閵夛絽濡藉┑?")
	fs.StringVar(&lastLoginFrom, "lastLoginFrom", "", "闂傚倸鍊搁崐鎼佸磹妞嬪海鐭嗗〒姘ｅ亾妤犵偞鐗犻、鏇㈡晜閽樺缃曢梻浣告啞閸旓箓宕伴弽顐㈩棜濠电姵纰嶉悡娆撴煕閹炬鎳庣粭锟犳⒑缂佹ɑ灏版繛鍙夛耿楠炲牓濡搁妷顔藉缓闂佺硶鍓濋〃鍛达綖椤忓牊鈷戦柛锔诲幗椤忕喓绱掗幓鎺戔挃闁瑰箍鍨归埥澶愬閻樿尙鐛╂俊鐐€栭崝鎴﹀垂鐟欏嫭鍙忛柕鍫濐槹閳锋垿姊婚崼鐔衡姇濠㈣泛瀚伴弻娑㈠籍閳ь剟鎮烽妷鈺婃晪闁挎繂顦粻缁樸亜閺冨洦顥夊ù婊勭矒濮婃椽宕ㄦ繝鍐ㄧ閻庢鍠楅崕濂稿焻閸洘鈷掗柛灞捐壘閳ь剚鎮傚畷鎰板箹娴ｅ摜锛欓梺褰掓？缁€浣哄閻熸壋鏀介柣妯诲墯閸ょ喎顭块懜闈涘缂佺姵鐩弻鈩冨緞鎼淬垻銆婂銈嗘煥椤﹂潧顫忓ú顏勭閹艰揪绲块悾闈涱渻閵堝繒绱伴柛妤€鍟块悾鐑藉箛閻楀牆鈧鏌ら幁鎺戝姢闁告ü绮欓幃宄邦煥閸愵€勵殽閻愭惌娈旀い顓滃姂瀹曘劑顢涘鍛Ц婵犵數濮伴崹濂稿春閺嶎厼绀夐柡宥庡幗閸嬪倹绻涢幋娆忕仾闁绘挸鍟伴幉绋款煥閸繄顦梺缁樻⒒椤戞洟鍩€椤戣法顦﹂柍钘夘槸铻ｉ梺鍨儛濞兼梹绻濈喊妯活潑闁搞劋鍗冲畷銉р偓锝庝簼濮?RFC3339 闂?YYYY-MM-DD")
	fs.StringVar(&lastLoginTo, "lastLoginTo", "", "闂傚倸鍊搁崐鎼佸磹妞嬪海鐭嗗〒姘ｅ亾妤犵偞鐗犻、鏇㈡晜閽樺缃曢梻浣告啞閸旓箓宕伴弽顐㈩棜濠电姵纰嶉悡娆撴煕閹炬鎳庣粭锟犳⒑缂佹ɑ灏版繛鍙夛耿楠炲牓濡搁妷顔藉缓闂佺硶鍓濋〃鍛达綖椤忓牊鈷戦柛锔诲幗椤忕喓绱掗幓鎺戔挃闁瑰箍鍨归埥澶愬閻樿尙鐛╂俊鐐€栭崝鎴﹀垂鐟欏嫭鍙忛柕鍫濐槹閳锋垿姊婚崼鐔衡姇濠㈣泛瀚伴弻娑㈠籍閳ь剟鎮烽妷鈺婃晪闁挎繂顦粻缁樸亜閺冨洦顥夊ù婊勭矒濮婃椽宕ㄦ繝鍐ㄧ閻庢鍠楅崕濂稿焻閸洘鈷掗柛灞捐壘閳ь剚鎮傚畷鎰板箹娴ｅ摜锛欓梺褰掓？缁€浣哄瑜版帗鐓欓梻鍌氼嚟鐠愪即鏌℃担鍓插剱闁靛洤瀚伴獮妯兼崉閻╂帇鍨介弻娑㈠Ω閿斿墽鐤勯梺鍝勭灱閸犳牕鐣峰鍡╂Ь闁汇埄鍨遍惄顖炲蓟濞戞瑧绡€闁告洦鍋勯獮瀣⒑閸濆嫮鐒跨紓宥佸亾濡炪倧闄勯悡锟犲蓟閻斿吋鍤嶉柕澹懐鍘掔紓鍌欑贰閸犳牠鎮ф繝鍌ゅ殫闁告洦鍨扮粻娑欍亜閹捐泛孝妤犵偞鍔欏缁樼瑹閳ь剟鍩€椤掑倸浠滈柤娲诲灡閺呭墎鈧稒菧娴滄粓鏌曡箛銉х？闁宠棄顦甸弻宥夋寠婢舵ɑ笑闁句紮缍侀弻娑滅疀閹惧彉绮?RFC3339 闂?YYYY-MM-DD")
	fs.StringVar(&gid, "gid", "", "闂?GID 闂佸搫顦弲娑樏洪敃鍌氱")
	fs.StringVar(&uid, "uid", "", "闂?UID 闂佸搫顦弲娑樏洪敃鍌氱")
	fs.Var(&output, "output", "闂傚倸鍊搁崐椋庣矆娓氣偓楠炴牠顢曚綅閸ヮ剦鏁嶉柣鎰綑娴滆鲸绻濋悽闈浶㈡繛灞傚€楃划缁樺鐎涙鍘甸梻鍌氬€搁顓⑺囬敃鍌涚厱婵ɑ鍓氬鎰版煏閸パ冾伃妤犵偞锕㈠畷锟犳倷閸忓憡鍋呴梻鍌欑閹诧繝宕濊箛娑樼；闁瑰墽绮埛鎺懨归敐鍫燁仩閻㈩垱鐩弻鐔煎传閵夘喚鍔搁梻鍥ь槸椤啰鈧綆浜滈銏ゆ煕韫囨梻鐭掗柡灞界Х椤т線鏌涢幘璺烘瀻妞ゎ偄绻愮叅妞ゅ繐瀚鍥煙閼圭増褰х紒鑼劋閹便劑宕惰濞撳鏌曢崼婵囶棞濞ｅ浂鍨辨穱濠囨嚑椤戣棄浜炬慨?闂?excel")
	fs.StringVar(&opts.ExcelPath, "excel", "", "export Excel file path (.xlsx)")

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
				return opts, fmt.Errorf("lastLoginFrom 闂傚倸鍊搁崐鎼佸磹妞嬪海鐭嗗〒姘ｅ亾妤犵偞鐗犻、鏇㈡晝閳ь剟鎮块濮愪簻闁规澘鐖煎顕€鏌涚€ｎ亶妯€闁哄矉缍侀獮姗€宕樺顔兼暔婵犵數鍋為崹顖炲垂瑜版帗鐓ラ柕鍫濇缁诲棝鏌曢崼婵嗏偓鍛婄妤ｅ啯鈷戦柛娑橈工婵偓闂佺顑嗛幑鍥ь潖缂佹ɑ濯撮柧蹇曟嚀缁楋繝姊洪悷鐗堟喐妞ゎ厼鐗撳﹢浣逛繆閻愬樊鍎忛悗娑掓櫊瀹曟顭ㄩ崼鐔哄帗閻熸粍绮撳畷婊堟偄婵傚缍庡┑鐐叉▕娴滄粍瀵奸悩缁樼厱闁哄洢鍔屾禍婵囩箾閸絽鐓愮紒缁樼箓閳绘捇宕归鐣屼壕闂備浇妗ㄥù鍥敋瑜旈、? %w", err)
			}
			dateRange.From = &from
		}
		if lastLoginTo != "" {
			to, err := parseTime(lastLoginTo)
			if err != nil {
				return opts, fmt.Errorf("lastLoginTo 闂傚倸鍊搁崐鎼佸磹妞嬪海鐭嗗〒姘ｅ亾妤犵偞鐗犻、鏇㈡晝閳ь剟鎮块濮愪簻闁规澘鐖煎顕€鏌涚€ｎ亶妯€闁哄矉缍侀獮姗€宕樺顔兼暔婵犵數鍋為崹顖炲垂瑜版帗鐓ラ柕鍫濇缁诲棝鏌曢崼婵嗏偓鍛婄妤ｅ啯鈷戦柛娑橈工婵偓闂佺顑嗛幑鍥ь潖缂佹ɑ濯撮柧蹇曟嚀缁楋繝姊洪悷鐗堟喐妞ゎ厼鐗撳﹢浣逛繆閻愬樊鍎忛悗娑掓櫊瀹曟顭ㄩ崼鐔哄帗閻熸粍绮撳畷婊堟偄婵傚缍庡┑鐐叉▕娴滄粍瀵奸悩缁樼厱闁哄洢鍔屾禍婵囩箾閸絽鐓愮紒缁樼箓閳绘捇宕归鐣屼壕闂備浇妗ㄥù鍥敋瑜旈、? %w", err)
			}
			dateRange.To = &to
		}
		params.LastLoginTime = dateRange
	}
	if gid != "" {
		parsed, err := strconv.ParseInt(gid, 10, 64)
		if err != nil {
			return opts, fmt.Errorf("gid 闂傚倸鍊搁崐鎼佸磹妞嬪海鐭嗗〒姘ｅ亾妤犵偞鐗犻、鏇㈠Χ閸モ晝鍘犻梻浣稿閸嬪懎煤閺嶎厼纾奸柕濞у嫬鏋戦棅顐㈡处閹峰綊鏁愭径濠勭杸闂佺粯顨呴悧濠傗枍閵忋倖鈷戠紓浣癸供閻掗箖鎮樿箛鏃傛噰闁诡垰鐗撳畷鐔碱敍濞戞帗瀚肩紓鍌氬€烽悞锕傛晝閳哄懏鍊块柣鎰靛墰缁犻箖鏌涘☉鍗炴灍缂佲偓閳ь剟姊? %w", err)
		}
		params.GID = &parsed
	}
	if uid != "" {
		parsed, err := strconv.ParseInt(uid, 10, 64)
		if err != nil {
			return opts, fmt.Errorf("uid 闂傚倸鍊搁崐鎼佸磹妞嬪海鐭嗗〒姘ｅ亾妤犵偞鐗犻、鏇㈠Χ閸モ晝鍘犻梻浣稿閸嬪懎煤閺嶎厼纾奸柕濞у嫬鏋戦棅顐㈡处閹峰綊鏁愭径濠勭杸闂佺粯顨呴悧濠傗枍閵忋倖鈷戠紓浣癸供閻掗箖鎮樿箛鏃傛噰闁诡垰鐗撳畷鐔碱敍濞戞帗瀚肩紓鍌氬€烽悞锕傛晝閳哄懏鍊块柣鎰靛墰缁犻箖鏌涘☉鍗炴灍缂佲偓閳ь剟姊? %w", err)
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
		return opts, fmt.Errorf("output 闂傚倸鍊搁崐鎼佸磹妞嬪海鐭嗗〒姘ｅ亾妤犵偛顦甸弫鎾绘偐閸愯弓鐢婚梻渚€娼чˇ顐﹀疾濞戞艾顥氶柛锔诲幗閸犳劙鏌ｅΔ鈧悧鍡欑箔閹烘挻鍙忛悷娆忓閸欌偓闂佸搫鐭夌紞浣割嚕椤曗偓瀹曟帒顫濋璺ㄥ笡缂傚倸鍊风欢锟犲磻閸曨厾鐭撶憸鐗堝笒閽冪喖鏌ㄥ┑鍡樺晵闁绘梻鍘х粻浼村箹鏉堝墽鍒版繛鎳峰嫮绡€? %s", output.value)
	}
	if opts.OutputFormat == "excel" && strings.TrimSpace(opts.ExcelPath) == "" {
		return opts, fmt.Errorf("濠电偠鎻紞鈧繛澶嬫礋瀵?output=excel 闂備礁鎼崯鍐测枖濞戞碍宕查柍褜鍓欓—鍐Χ閸モ晛绗￠悷婊堫暒閻掞妇绮?-excel 闂備礁鎼崐绋棵洪敐鍛瀻闁靛繈鍨哄畷澶嬨亜閺嶃劍鐨戠紒?")
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
		fmt.Fprintln(os.Stderr, "闂傚倸鍊搁崐鎼佸磹閻戣姤鍊块柨鏇楀亾妞ゎ亜鍟村畷褰掝敋閸涱垰濮洪梻浣侯潒閸曞灚鐣剁紓浣插亾濠㈣泛澶囬崑鎾荤嵁閸喖濮庡┑鐐额嚋缁犳挸鐣?")
		fmt.Fprintln(os.Stderr, "  c-eyes user-group scan [闂傚倸鍊搁崐鎼佸磹妞嬪海鐭嗗〒姘ｅ亾妤犵偛顦甸弫鎾绘偐閸愯弓鐢婚梻渚€娼чˇ顐﹀疾濞戞艾顥氶柛锔诲幗閸犳劙鏌ｅΔ鈧悧鍡欑箔閹烘挻鍙忛悷娆忓閸欌偓闂?[-output json|excel] [-excel out.xlsx]")
		fmt.Fprintln(os.Stderr, "\n闂傚倸鍊搁崐鎼佸磹妞嬪海鐭嗗〒姘ｅ亾妤犵偛顦甸弫鎾绘偐閸愯弓鐢婚梻渚€娼чˇ顐﹀疾濞戞艾顥氶柛锔诲幗閸犳劙鏌ｅΔ鈧悧鍡欑箔閹烘挻鍙?")
		fs.PrintDefaults()
	}

	var opts userGroupScanOptions
	var hostname, ip, name, gid string
	var groups intSliceFlag
	output := outputModeFlag{value: "json"}

	fs.Var(&groups, "groups", "闂備礁婀遍…鍫ニ囨潏鈺佸灊?ID 闂佸搫顦弲娑樏洪敃鍌氱闁靛牆顦伴弲顒傗偓鍏夊亾闁告洏鍔屾禍鐐繆閵堝倸浜鹃悷婊勬緲濞尖€崇暦濮樿泛骞㈡繛鎴炵懐閸?")
	fs.StringVar(&hostname, "hostname", "", "闂備礁婀遍…鍫ニ囬閿亾闂堟稓鐒哥€殿喚鏁诲畷顐﹀礋椤掆偓閳ь剚濞婂鍫曞煛娴ｇ懓顦╅梺?")
	fs.StringVar(&ip, "ip", "", "闂?IP 闂佸搫顦弲娑樏洪敃鍌氱")
	fs.StringVar(&name, "name", "", "闂佸湱顭堥ˇ杈╁垝瀹ュ瑙︾€广儱鐗忕粻鏍ㄧ節?")
	fs.StringVar(&gid, "gid", "", "闂?GID 闂佸搫顦弲娑樏洪敃鍌氱")
	fs.Var(&output, "output", "闂傚倸鍊搁崐椋庣矆娓氣偓楠炴牠顢曚綅閸ヮ剦鏁嶉柣鎰綑娴滆鲸绻濋悽闈浶㈡繛灞傚€楃划缁樺鐎涙鍘甸梻鍌氬€搁顓⑺囬敃鍌涚厱婵ɑ鍓氬鎰版煏閸パ冾伃妤犵偞锕㈠畷锟犳倷閸忓憡鍋呴梻鍌欑閹诧繝宕濊箛娑樼；闁瑰墽绮埛鎺懨归敐鍫燁仩閻㈩垱鐩弻鐔煎传閵夘喚鍔搁梻鍥ь槸椤啰鈧綆浜滈銏ゆ煕韫囨梻鐭掗柡灞界Х椤т線鏌涢幘璺烘瀻妞ゎ偄绻愮叅妞ゅ繐瀚鍥煙閼圭増褰х紒鑼劋閹便劑宕惰濞撳鏌曢崼婵囶棞濞ｅ浂鍨辨穱濠囨嚑椤戣棄浜炬慨?闂?excel")
	fs.StringVar(&opts.ExcelPath, "excel", "", "闁诲海鏁搁崢褔宕?Excel 闂佸搫鍊稿ú锝呪枎閵忋垺宕夋い鏍ㄦ皑缁愮偤鏌?xlsx闂?")

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
			return opts, fmt.Errorf("gid 闂傚倸鍊搁崐鎼佸磹妞嬪海鐭嗗〒姘ｅ亾妤犵偞鐗犻、鏇㈠Χ閸モ晝鍘犻梻浣稿閸嬪懎煤閺嶎厼纾奸柕濞у嫬鏋戦棅顐㈡处閹峰綊鏁愭径濠勭杸闂佺粯顨呴悧濠傗枍閵忋倖鈷戠紓浣癸供閻掗箖鎮樿箛鏃傛噰闁诡垰鐗撳畷鐔碱敍濞戞帗瀚肩紓鍌氬€烽悞锕傛晝閳哄懏鍊块柣鎰靛墰缁犻箖鏌涘☉鍗炴灍缂佲偓閳ь剟姊? %w", err)
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
		return opts, fmt.Errorf("output 闂傚倸鍊搁崐鎼佸磹妞嬪海鐭嗗〒姘ｅ亾妤犵偛顦甸弫鎾绘偐閸愯弓鐢婚梻渚€娼чˇ顐﹀疾濞戞艾顥氶柛锔诲幗閸犳劙鏌ｅΔ鈧悧鍡欑箔閹烘挻鍙忛悷娆忓閸欌偓闂佸搫鐭夌紞浣割嚕椤曗偓瀹曟帒顫濋璺ㄥ笡缂傚倸鍊风欢锟犲磻閸曨厾鐭撶憸鐗堝笒閽冪喖鏌ㄥ┑鍡樺晵闁绘梻鍘х粻浼村箹鏉堝墽鍒版繛鎳峰嫮绡€? %s", output.value)
	}
	if opts.OutputFormat == "excel" && strings.TrimSpace(opts.ExcelPath) == "" {
		return opts, fmt.Errorf("濠电偠鎻紞鈧繛澶嬫礋瀵?output=excel 闂備礁鎼崯鍐测枖濞戞碍宕查柍褜鍓欓—鍐Χ閸モ晛绗￠悷婊堫暒閻掞妇绮?-excel 闂備礁鎼崐绋棵洪敐鍛瀻闁靛繈鍨哄畷澶嬨亜閺嶃劍鐨戠紒?")
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
		fmt.Fprintln(os.Stderr, "闂傚倸鍊搁崐鎼佸磹閻戣姤鍊块柨鏇楀亾妞ゎ亜鍟村畷褰掝敋閸涱垰濮洪梻浣侯潒閸曞灚鐣剁紓浣插亾濠㈣泛澶囬崑鎾荤嵁閸喖濮庡┑鐐额嚋缁犳挸鐣?")
		fmt.Fprintln(os.Stderr, "  c-eyes port-scan [闂傚倸鍊搁崐鎼佸磹妞嬪海鐭嗗〒姘ｅ亾妤犵偛顦甸弫鎾绘偐閸愯弓鐢婚梻渚€娼чˇ顐﹀疾濞戞艾顥氶柛锔诲幗閸犳劙鏌ｅΔ鈧悧鍡欑箔閹烘挻鍙忛悷娆忓閸欌偓闂?[-output json|excel] [-excel out.xlsx]")
		fmt.Fprintln(os.Stderr, "\n闂傚倸鍊搁崐鎼佸磹妞嬪海鐭嗗〒姘ｅ亾妤犵偛顦甸弫鎾绘偐閸愯弓鐢婚梻渚€娼чˇ顐﹀疾濞戞艾顥氶柛锔诲幗閸犳劙鏌ｅΔ鈧悧鍡欑箔閹烘挻鍙?")
		fs.PrintDefaults()
	}

	var opts portScanOptions
	var hostname, ip, bindIP, processName, mode string
	var groups intSliceFlag
	var protos stringSliceFlag
	var port optionalInt
	output := outputModeFlag{value: "json"}

	fs.Var(&groups, "groups", "闂備礁婀遍…鍫ニ囨潏鈺佸灊?ID 闂佸搫顦弲娑樏洪敃鍌氱闁靛牆顦伴弲顒傗偓鍏夊亾闁告洏鍔屾禍鐐繆閵堝倸浜鹃悷婊勬緲濞尖€崇暦濮樿泛骞㈡繛鎴炵懐閸?")
	fs.StringVar(&hostname, "hostname", "", "闂備礁婀遍…鍫ニ囬閿亾闂堟稓鐒哥€殿喚鏁诲畷顐﹀礋椤掆偓閳ь剚濞婂鍫曞煛娴ｇ懓顦╅梺?")
	fs.StringVar(&ip, "ip", "", "闂?IP 闂佸搫顦弲娑樏洪敃鍌氱")
	fs.Var(&protos, "proto", "Filter by protocol list (comma-separated)")
	fs.Var(&port, "port", "闂佸湱顭堥ˇ閬嶎敂椤掑嫬鐭楅柨婵嗙墢缁犳牗绻?")
	fs.StringVar(&bindIP, "bindIp", "", "闂備礁婀遍…鍫ニ囨潏鈺佸灊闁挎棃鏁崑?IP 闂佸搫顦弲娑樏洪敃鍌氱")
	fs.StringVar(&processName, "processName", "", "闂備礁婀遍…鍫ニ囧畷鍥ㄥ床婵☆垵鍋愰惌娆撴倵閿濆簼绨奸柛濠冨▕瀵爼鍩℃担鐟邦槱闂?")
	fs.StringVar(&mode, "mode", string(portscan.ScanModeTCPConnect), "闂傚倸鍊搁崐鎼佸磹瀹勬噴褰掑炊椤掑﹦绋忔繝銏ｅ煐閸旓箓寮繝鍥ㄧ厸鐎广儱楠搁獮鏍棯閹岀吋闁哄本绋戦埥澶愬础閻愭彃顒滈梻浣规偠閸婃牕煤閻旂厧钃熸繛鎴旀噰閳ь剨绠撻獮瀣攽閸ャ劎鏋冮梻鍌欒兌缁垰顫忔繝姘偍鐟滄棃骞冨Ο铏规殾闁搞儻绲芥禍楣冩偡濞嗗繐顏紒鈧埀顒€鈹戦悙鑼勾闁告梹鍨挎俊瀛樼瑹閳ь剙鐣烽妸褉鍋撳☉娅辨岸骞忓ú顏呪拺闁革富鍙庨悞鐐箾鐎电鍘撮柛鈺侊躬瀵挳鎮㈢紙鐘电泿闂備礁婀遍崕銈咁潖瑜版帒姹查柛?connect 闂?tcp-syn")
	fs.Var(&output, "output", "闂傚倸鍊搁崐椋庣矆娓氣偓楠炴牠顢曚綅閸ヮ剦鏁嶉柣鎰綑娴滆鲸绻濋悽闈浶㈡繛灞傚€楃划缁樺鐎涙鍘甸梻鍌氬€搁顓⑺囬敃鍌涚厱婵ɑ鍓氬鎰版煏閸パ冾伃妤犵偞锕㈠畷锟犳倷閸忓憡鍋呴梻鍌欑閹诧繝宕濊箛娑樼；闁瑰墽绮埛鎺懨归敐鍫燁仩閻㈩垱鐩弻鐔煎传閵夘喚鍔搁梻鍥ь槸椤啰鈧綆浜滈銏ゆ煕韫囨梻鐭掗柡灞界Х椤т線鏌涢幘璺烘瀻妞ゎ偄绻愮叅妞ゅ繐瀚鍥煙閼圭増褰х紒鑼劋閹便劑宕惰濞撳鏌曢崼婵囶棞濞ｅ浂鍨辨穱濠囨嚑椤戣棄浜炬慨?闂?excel")
	fs.StringVar(&opts.ExcelPath, "excel", "", "闁诲海鏁搁崢褔宕?Excel 闂佸搫鍊稿ú锝呪枎閵忋垺宕夋い鏍ㄦ皑缁愮偤鏌?xlsx闂?")

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
		return opts, fmt.Errorf("mode 闂傚倸鍊搁崐鎼佸磹妞嬪海鐭嗗〒姘ｅ亾妤犵偛顦甸弫鎾绘偐閸愯弓鐢婚梻渚€娼чˇ顐﹀疾濞戞艾顥氶柛锔诲幗閸犳劙鏌ｅΔ鈧悧鍡欑箔閹烘挻鍙忛悷娆忓閸欌偓闂佸搫鐭夌紞浣割嚕椤曗偓瀹曟帒顫濋璺ㄥ笡缂傚倸鍊风欢锟犲磻閸曨厾鐭撶憸鐗堝笒閽冪喖鏌ㄥ┑鍡樺晵闁绘梻鍘х粻浼村箹鏉堝墽鍒版繛鎳峰嫮绡€? %s", mode)
	}

	if strings.TrimSpace(opts.ExcelPath) != "" && !output.set {
		output.value = "excel"
	}

	outputMode := strings.ToLower(strings.TrimSpace(output.value))
	switch outputMode {
	case "json", "excel":
		opts.OutputFormat = outputMode
	default:
		return opts, fmt.Errorf("output 闂傚倸鍊搁崐鎼佸磹妞嬪海鐭嗗〒姘ｅ亾妤犵偛顦甸弫鎾绘偐閸愯弓鐢婚梻渚€娼чˇ顐﹀疾濞戞艾顥氶柛锔诲幗閸犳劙鏌ｅΔ鈧悧鍡欑箔閹烘挻鍙忛悷娆忓閸欌偓闂佸搫鐭夌紞浣割嚕椤曗偓瀹曟帒顫濋璺ㄥ笡缂傚倸鍊风欢锟犲磻閸曨厾鐭撶憸鐗堝笒閽冪喖鏌ㄥ┑鍡樺晵闁绘梻鍘х粻浼村箹鏉堝墽鍒版繛鎳峰嫮绡€? %s", output.value)
	}
	if opts.OutputFormat == "excel" && strings.TrimSpace(opts.ExcelPath) == "" {
		return opts, fmt.Errorf("濠电偠鎻紞鈧繛澶嬫礋瀵?output=excel 闂備礁鎼崯鍐测枖濞戞碍宕查柍褜鍓欓—鍐Χ閸モ晛绗￠悷婊堫暒閻掞妇绮?-excel 闂備礁鎼崐绋棵洪敐鍛瀻闁靛繈鍨哄畷澶嬨亜閺嶃劍鐨戠紒?")
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
		fmt.Fprintln(os.Stderr, "闂傚倸鍊搁崐鎼佸磹閻戣姤鍊块柨鏇楀亾妞ゎ亜鍟村畷褰掝敋閸涱垰濮洪梻浣侯潒閸曞灚鐣剁紓浣插亾濠㈣泛澶囬崑鎾荤嵁閸喖濮庡┑鐐额嚋缁犳挸鐣?")
		fmt.Fprintln(os.Stderr, "  c-eyes startup-scan [闂傚倸鍊搁崐鎼佸磹妞嬪海鐭嗗〒姘ｅ亾妤犵偛顦甸弫鎾绘偐閸愯弓鐢婚梻渚€娼чˇ顐﹀疾濞戞艾顥氶柛锔诲幗閸犳劙鏌ｅΔ鈧悧鍡欑箔閹烘挻鍙忛悷娆忓閸欌偓闂?[-output json|excel] [-excel out.xlsx]")
		fmt.Fprintln(os.Stderr, "\n闂傚倸鍊搁崐鎼佸磹妞嬪海鐭嗗〒姘ｅ亾妤犵偛顦甸弫鎾绘偐閸愯弓鐢婚梻渚€娼чˇ顐﹀疾濞戞艾顥氶柛锔诲幗閸犳劙鏌ｅΔ鈧悧鍡欑箔閹烘挻鍙?")
		fs.PrintDefaults()
	}

	var opts startupScanOptions
	var hostname, ip, name, showName, user, publisher string
	var groups, initLevel, startType intSliceFlag
	var defaultOpen, isXinetd boolSliceFlag
	var enable optionalBool
	output := outputModeFlag{value: "json"}

	fs.Var(&groups, "groups", "闂備礁婀遍…鍫ニ囨潏鈺佸灊?ID 闂佸搫顦弲娑樏洪敃鍌氱闁靛牆顦伴弲顒傗偓鍏夊亾闁告洏鍔屾禍鐐繆閵堝倸浜鹃悷婊勬緲濞尖€崇暦濮樿泛骞㈡繛鎴炵懐閸?")
	fs.StringVar(&hostname, "hostname", "", "闂備礁婀遍…鍫ニ囬閿亾闂堟稓鐒哥€殿喚鏁诲畷顐﹀礋椤掆偓閳ь剚濞婂鍫曞煛娴ｇ懓顦╅梺?")
	fs.StringVar(&ip, "ip", "", "闂?IP 闂佸搫顦弲娑樏洪敃鍌氱")
	fs.StringVar(&name, "name", "", "闂佸湱顭堥ˇ鐢稿Υ瀹ュ鍎庢い鏂垮悑閸婂磭绱掓径瀣€滅紒璇插暙椤?")
	fs.Var(&initLevel, "initLevel", "闂?init level 闁哄鏅涘ú锕傚箮閵堝鏅柛锔惧瀶nux闂?")
	fs.Var(&defaultOpen, "defaultOpen", "闂佸湱顭堥ˇ鐢靛垝椤栨粍濯奸柕鍫濇噺閸庢瑩鏌ｉ～顒€濡垮┑顔芥倐楠炩偓濞达絿鏅粻鏍ㄧ節婵炲灝鈧呮濮楃導nux闂佹寧绋戦鎼憉e/false闂?")
	fs.Var(&isXinetd, "isXinetd", "闂?xinetd 婵＄偑鍊楅、濠勬崲閸愵煈鐓ラ柕鍫濈箳缁€鍑﹊nux闂佹寧绋戦鎼憉e/false闂?")
	fs.StringVar(&showName, "showName", "", "闂佸湱顭堥ˇ鏉课熸径宀€鐭嗛柛婵嗗閸婂磭绱掓径瀣€滅紒璇插暙椤劑濡惰箛鏇狀槱Windows闂?")
	fs.StringVar(&user, "user", "", "闂佸湱顭堥ˇ閬嶅极閵堝绠ｉ柣銈庡灣缁犳牗绻?")
	fs.Var(&enable, "enable", "闂佸湱顭堥ˇ顖炲箚鎼淬劍鍋ㄩ柕濞у唭锕傛煙椤戞寧绁扮紒璇插暙椤劑濡惰箛鏇狀槱Windows闂佹寧绋戦鎼憉e/false闂?")
	fs.Var(&startType, "startType", "闂佸湱顭堥ˇ顖炲箚鎼淬劌绀夐柕濞у棭娼堕梺鎼炲妼椤戝牏鎹㈤崘顭戠叆闁靛牆绻掔粈鍒塱ndows闂?")
	fs.StringVar(&publisher, "publisher", "", "闂佸湱顭堥ˇ顖濄亹閸屾粍鏆滈柛鎰靛幐閸嬫捇宕ㄩ幍顔剧暫濠电姴顭堥崐褏妲愬绉坣dows闂?")
	fs.Var(&output, "output", "闂傚倸鍊搁崐椋庣矆娓氣偓楠炴牠顢曚綅閸ヮ剦鏁嶉柣鎰綑娴滆鲸绻濋悽闈浶㈡繛灞傚€楃划缁樺鐎涙鍘甸梻鍌氬€搁顓⑺囬敃鍌涚厱婵ɑ鍓氬鎰版煏閸パ冾伃妤犵偞锕㈠畷锟犳倷閸忓憡鍋呴梻鍌欑閹诧繝宕濊箛娑樼；闁瑰墽绮埛鎺懨归敐鍫燁仩閻㈩垱鐩弻鐔煎传閵夘喚鍔搁梻鍥ь槸椤啰鈧綆浜滈銏ゆ煕韫囨梻鐭掗柡灞界Х椤т線鏌涢幘璺烘瀻妞ゎ偄绻愮叅妞ゅ繐瀚鍥煙閼圭増褰х紒鑼劋閹便劑宕惰濞撳鏌曢崼婵囶棞濞ｅ浂鍨辨穱濠囨嚑椤戣棄浜炬慨?闂?excel")
	fs.StringVar(&opts.ExcelPath, "excel", "", "闁诲海鏁搁崢褔宕?Excel 闂佸搫鍊稿ú锝呪枎閵忋垺宕夋い鏍ㄦ皑缁愮偤鏌?xlsx闂?")

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
		return opts, fmt.Errorf("output 闂傚倸鍊搁崐鎼佸磹妞嬪海鐭嗗〒姘ｅ亾妤犵偛顦甸弫鎾绘偐閸愯弓鐢婚梻渚€娼чˇ顐﹀疾濞戞艾顥氶柛锔诲幗閸犳劙鏌ｅΔ鈧悧鍡欑箔閹烘挻鍙忛悷娆忓閸欌偓闂佸搫鐭夌紞浣割嚕椤曗偓瀹曟帒顫濋璺ㄥ笡缂傚倸鍊风欢锟犲磻閸曨厾鐭撶憸鐗堝笒閽冪喖鏌ㄥ┑鍡樺晵闁绘梻鍘х粻浼村箹鏉堝墽鍒版繛鎳峰嫮绡€? %s", output.value)
	}
	if opts.OutputFormat == "excel" && strings.TrimSpace(opts.ExcelPath) == "" {
		return opts, fmt.Errorf("濠电偠鎻紞鈧繛澶嬫礋瀵?output=excel 闂備礁鎼崯鍐测枖濞戞碍宕查柍褜鍓欓—鍐Χ閸モ晛绗￠悷婊堫暒閻掞妇绮?-excel 闂備礁鎼崐绋棵洪敐鍛瀻闁靛繈鍨哄畷澶嬨亜閺嶃劍鐨戠紒?")
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
		fmt.Fprintln(os.Stderr, "闂傚倸鍊搁崐鎼佸磹閻戣姤鍊块柨鏇楀亾妞ゎ亜鍟村畷褰掝敋閸涱垰濮洪梻浣侯潒閸曞灚鐣剁紓浣插亾濠㈣泛澶囬崑鎾荤嵁閸喖濮庡┑鐐额嚋缁犳挸鐣?")
		fmt.Fprintln(os.Stderr, "  c-eyes scheduled-task-scan [闂傚倸鍊搁崐鎼佸磹妞嬪海鐭嗗〒姘ｅ亾妤犵偛顦甸弫鎾绘偐閸愯弓鐢婚梻渚€娼чˇ顐﹀疾濞戞艾顥氶柛锔诲幗閸犳劙鏌ｅΔ鈧悧鍡欑箔閹烘挻鍙忛悷娆忓閸欌偓闂?[-output json|excel] [-excel out.xlsx]")
		fmt.Fprintln(os.Stderr, "\n闂傚倸鍊搁崐鎼佸磹妞嬪海鐭嗗〒姘ｅ亾妤犵偛顦甸弫鎾绘偐閸愯弓鐢婚梻渚€娼чˇ顐﹀疾濞戞艾顥氶柛锔诲幗閸犳劙鏌ｅΔ鈧悧鍡欑箔閹烘挻鍙?")
		fs.PrintDefaults()
	}

	var opts scheduledTaskScanOptions
	var hostname, ip, execPath, conf, taskTimeFrom, taskTimeTo string
	var groups intSliceFlag
	var users, taskTypes stringSliceFlag
	output := outputModeFlag{value: "json"}

	fs.Var(&groups, "groups", "闂備礁婀遍…鍫ニ囨潏鈺佸灊?ID 闂佸搫顦弲娑樏洪敃鍌氱闁靛牆顦伴弲顒傗偓鍏夊亾闁告洏鍔屾禍鐐繆閵堝倸浜鹃悷婊勬緲濞尖€崇暦濮樿泛骞㈡繛鎴炵懐閸?")
	fs.StringVar(&hostname, "hostname", "", "闂備礁婀遍…鍫ニ囬閿亾闂堟稓鐒哥€殿喚鏁诲畷顐﹀礋椤掆偓閳ь剚濞婂鍫曞煛娴ｇ懓顦╅梺?")
	fs.StringVar(&ip, "ip", "", "闂?IP 闂佸搫顦弲娑樏洪敃鍌氱")
	fs.Var(&users, "user", "闂佸湱顭堥ˇ閬嶅极閵堝绠ｉ柣銈庡灣缁犳牗绻濇繛鍨偓褏妲愬┑瀣劵婵°倐鍋撶憸鏉挎健瀹曟岸宕卞☉娆樺悩")
	fs.StringVar(&execPath, "execPath", "", "闂備礁婀遍…鍫ニ囬婵勪汗闁哄被鍎辩粻銉ф喐閹达负鈧線骞嬮悩鍐茬／濡炪倖鐗楀銊х玻閻愬搫绾ч柍杞扮劍婢跺嫰鏌?")
	fs.StringVar(&conf, "conf", "", "闂佸湱顭堥ˇ鐢稿储閵堝洨纾炬い鏃傚帶閺佸爼鎮楅崷顓ф敯缂佽鍟…?")
	fs.StringVar(&taskTimeFrom, "taskTimeFrom", "", "濠电姷鏁告慨鐑藉极閹间礁纾绘繛鎴欏焺閺佸銇勯幘璺烘瀾闁告瑥绻愯灃闁挎繂鎳庨弸銈夋煛娴ｅ壊鍎戦柟鎻掓啞閹棃濡搁妷褏鏉介梻渚€娼ц墝闁哄懏绮撳畷鎴﹀礋椤栨稓鍘介梺瑙勫礃濞呮洟骞戦敐澶嬬厽妞ゆ劑鍨归顓熸叏婵犲啯銇濈€规洘绮撻獮鎾诲箳瀹ュ洤鍤┑鐘垫暩閸嬫稑顕ｉ崼鏇熸櫇闁靛繈鍊曢弸浣衡偓骞垮劚椤︿即宕戦崟顖涚厱闊洦娲栫敮璺好归悪鈧崹鍫曞箖瀹勯偊鐓ラ柛鏇ㄥ墻濡啴鏌﹀Ο鐓庢灈闁哄瞼鍠栭獮鎴﹀箛闂堟稒顔勭紓浣哄亾閸庢娊鈥﹂悜钘夎摕闁靛鍎弨浠嬫煕閳锯偓閺呮粍鏅ラ梻鍌欑閹碱偊骞忕€ｎ喖绀堥柣鏃傚帶缁犳牗鎱ㄥ璇蹭壕闂佽鍠楅悷鈺佄涢崘銊㈡婵°倐鍋撴い銉﹀哺濮婄粯鎷呴崨濠冨創濠碘槅鍋呴悷褔宕氶幒妤€绠婚悹鍥蔼閹?RFC3339 闂?YYYY-MM-DD")
	fs.StringVar(&taskTimeTo, "taskTimeTo", "", "濠电姷鏁告慨鐑藉极閹间礁纾绘繛鎴欏焺閺佸銇勯幘璺烘瀾闁告瑥绻愯灃闁挎繂鎳庨弸銈夋煛娴ｅ壊鍎戦柟鎻掓啞閹棃濡搁妷褏鏉介梻渚€娼ц墝闁哄懏绮撳畷鎴﹀礋椤栨稓鍘介梺瑙勫礃濞呮洟骞戦敐澶嬬厽妞ゆ劑鍨归顓熸叏婵犲啯銇濈€规洘绮撻獮鎾诲箳瀹ュ洤鍤┑鐘垫暩閸嬫稑顕ｉ崼鏇熸櫇闁靛繈鍊曢弸浣衡偓骞垮劚椤︿即宕戦崟顖涚叄闊洦鎸荤拹锟犳煥濞戞瑧绠栫紒缁樼⊕濞煎繘宕滆閸╁矂姊虹涵鍛撶紒顔肩Ч瀵煡宕奸弴鐑嗘綂闂侀潧鐗嗗Λ娑㈠储闁秵鐓熼幖鎼灣閸掓澘顭胯濞撮鍒掗弮鍫晪闁逞屽墴瀵鍩勯崘鈺侇€撻梺鍛婄缚閸庢盯濡堕崥銈呯秺閹亪宕ㄩ婊勬闂備浇顕栭崰妤呮偡閳哄懌鈧礁螖娴ｇ懓顎撻柣鐘叉礌閳ь剝娅曢弳顏堟⒒?RFC3339 闂?YYYY-MM-DD")
	fs.Var(&taskTypes, "taskType", "婵炲濮鹃褎鎱ㄩ悢铏瑰暗閻犲洩灏欓埀顒勬敱濞煎宕堕妸锕€袘闂佹寧绋戞總鏃傚垝鎼淬劌缁╂い鏍ㄧ☉閻?CRONTAB/AT/BATCH闂佹寧绋戦惌鍌炲焵椤掍緡娈旂憸鏉挎健瀹曟岸宕卞☉娆樺悩")
	fs.Var(&output, "output", "闂傚倸鍊搁崐椋庣矆娓氣偓楠炴牠顢曚綅閸ヮ剦鏁嶉柣鎰綑娴滆鲸绻濋悽闈浶㈡繛灞傚€楃划缁樺鐎涙鍘甸梻鍌氬€搁顓⑺囬敃鍌涚厱婵ɑ鍓氬鎰版煏閸パ冾伃妤犵偞锕㈠畷锟犳倷閸忓憡鍋呴梻鍌欑閹诧繝宕濊箛娑樼；闁瑰墽绮埛鎺懨归敐鍫燁仩閻㈩垱鐩弻鐔煎传閵夘喚鍔搁梻鍥ь槸椤啰鈧綆浜滈銏ゆ煕韫囨梻鐭掗柡灞界Х椤т線鏌涢幘璺烘瀻妞ゎ偄绻愮叅妞ゅ繐瀚鍥煙閼圭増褰х紒鑼劋閹便劑宕惰濞撳鏌曢崼婵囶棞濞ｅ浂鍨辨穱濠囨嚑椤戣棄浜炬慨?闂?excel")
	fs.StringVar(&opts.ExcelPath, "excel", "", "闁诲海鏁搁崢褔宕?Excel 闂佸搫鍊稿ú锝呪枎閵忋垺宕夋い鏍ㄦ皑缁愮偤鏌?xlsx闂?")

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
				return opts, fmt.Errorf("taskTimeFrom 闂傚倸鍊搁崐鎼佸磹妞嬪海鐭嗗〒姘ｅ亾妤犵偞鐗犻、鏇㈡晝閳ь剟鎮块濮愪簻闁规澘鐖煎顕€鏌涚€ｎ亶妯€闁哄矉缍侀獮姗€宕樺顔兼暔婵犵數鍋為崹顖炲垂瑜版帗鐓ラ柕鍫濇缁诲棝鏌曢崼婵嗏偓鍛婄妤ｅ啯鈷戦柛娑橈工婵偓闂佺顑嗛幑鍥ь潖缂佹ɑ濯撮柧蹇曟嚀缁楋繝姊洪悷鐗堟喐妞ゎ厼鐗撳﹢浣逛繆閻愬樊鍎忛悗娑掓櫊瀹曟顭ㄩ崼鐔哄帗閻熸粍绮撳畷婊堟偄婵傚缍庡┑鐐叉▕娴滄粍瀵奸悩缁樼厱闁哄洢鍔屾禍婵囩箾閸絽鐓愮紒缁樼箓閳绘捇宕归鐣屼壕闂備浇妗ㄥù鍥敋瑜旈、? %w", err)
			}
			dr.From = &from
		}
		if taskTimeTo != "" {
			to, err := parseTime(taskTimeTo)
			if err != nil {
				return opts, fmt.Errorf("taskTimeTo 闂傚倸鍊搁崐鎼佸磹妞嬪海鐭嗗〒姘ｅ亾妤犵偞鐗犻、鏇㈡晝閳ь剟鎮块濮愪簻闁规澘鐖煎顕€鏌涚€ｎ亶妯€闁哄矉缍侀獮姗€宕樺顔兼暔婵犵數鍋為崹顖炲垂瑜版帗鐓ラ柕鍫濇缁诲棝鏌曢崼婵嗏偓鍛婄妤ｅ啯鈷戦柛娑橈工婵偓闂佺顑嗛幑鍥ь潖缂佹ɑ濯撮柧蹇曟嚀缁楋繝姊洪悷鐗堟喐妞ゎ厼鐗撳﹢浣逛繆閻愬樊鍎忛悗娑掓櫊瀹曟顭ㄩ崼鐔哄帗閻熸粍绮撳畷婊堟偄婵傚缍庡┑鐐叉▕娴滄粍瀵奸悩缁樼厱闁哄洢鍔屾禍婵囩箾閸絽鐓愮紒缁樼箓閳绘捇宕归鐣屼壕闂備浇妗ㄥù鍥敋瑜旈、? %w", err)
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
		return opts, fmt.Errorf("output 闂傚倸鍊搁崐鎼佸磹妞嬪海鐭嗗〒姘ｅ亾妤犵偛顦甸弫鎾绘偐閸愯弓鐢婚梻渚€娼чˇ顐﹀疾濞戞艾顥氶柛锔诲幗閸犳劙鏌ｅΔ鈧悧鍡欑箔閹烘挻鍙忛悷娆忓閸欌偓闂佸搫鐭夌紞浣割嚕椤曗偓瀹曟帒顫濋璺ㄥ笡缂傚倸鍊风欢锟犲磻閸曨厾鐭撶憸鐗堝笒閽冪喖鏌ㄥ┑鍡樺晵闁绘梻鍘х粻浼村箹鏉堝墽鍒版繛鎳峰嫮绡€? %s", output.value)
	}
	if opts.OutputFormat == "excel" && strings.TrimSpace(opts.ExcelPath) == "" {
		return opts, fmt.Errorf("濠电偠鎻紞鈧繛澶嬫礋瀵?output=excel 闂備礁鎼崯鍐测枖濞戞碍宕查柍褜鍓欓—鍐Χ閸モ晛绗￠悷婊堫暒閻掞妇绮?-excel 闂備礁鎼崐绋棵洪敐鍛瀻闁靛繈鍨哄畷澶嬨亜閺嶃劍鐨戠紒?")
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
		fmt.Fprintln(os.Stderr, "闂傚倸鍊搁崐鎼佸磹閻戣姤鍊块柨鏇楀亾妞ゎ亜鍟村畷褰掝敋閸涱垰濮洪梻浣侯潒閸曞灚鐣剁紓浣插亾濠㈣泛澶囬崑鎾荤嵁閸喖濮庡┑鐐额嚋缁犳挸鐣?")
		fmt.Fprintln(os.Stderr, "  c-eyes environment-scan [闂傚倸鍊搁崐鎼佸磹妞嬪海鐭嗗〒姘ｅ亾妤犵偛顦甸弫鎾绘偐閸愯弓鐢婚梻渚€娼чˇ顐﹀疾濞戞艾顥氶柛锔诲幗閸犳劙鏌ｅΔ鈧悧鍡欑箔閹烘挻鍙忛悷娆忓閸欌偓闂?[-output json|excel] [-excel out.xlsx]")
		fmt.Fprintln(os.Stderr, "\n闂傚倸鍊搁崐鎼佸磹妞嬪海鐭嗗〒姘ｅ亾妤犵偛顦甸弫鎾绘偐閸愯弓鐢婚梻渚€娼чˇ顐﹀疾濞戞艾顥氶柛锔诲幗閸犳劙鏌ｅΔ鈧悧鍡欑箔閹烘挻鍙?")
		fs.PrintDefaults()
	}

	var opts environmentScanOptions
	var hostname, ip, key, value, user string
	var groups intSliceFlag
	var sysEnv boolSliceFlag
	output := outputModeFlag{value: "json"}

	fs.Var(&groups, "groups", "闂備礁婀遍…鍫ニ囨潏鈺佸灊?ID 闂佸搫顦弲娑樏洪敃鍌氱闁靛牆顦伴弲顒傗偓鍏夊亾闁告洏鍔屾禍鐐繆閵堝倸浜鹃悷婊勬緲濞尖€崇暦濮樿泛骞㈡繛鎴炵懐閸?")
	fs.StringVar(&hostname, "hostname", "", "闂備礁婀遍…鍫ニ囬閿亾闂堟稓鐒哥€殿喚鏁诲畷顐﹀礋椤掆偓閳ь剚濞婂鍫曞煛娴ｇ懓顦╅梺?")
	fs.StringVar(&ip, "ip", "", "闂?IP 闂佸搫顦弲娑樏洪敃鍌氱")
	fs.StringVar(&key, "key", "", "闂傚倸鍊搁崐鎼佸磹妞嬪海鐭嗗ù锝夋交閼板潡姊洪鈧粔顕€鍩€椤掑﹦鐣电€规洖銈告俊椋庘偓锝庝簼閸犳﹢鏌＄仦鑺ヮ棞妞ゆ挸銈稿畷鎯邦槾闁靛牞绠撳缁樻媴閾忓箍鈧﹪鏌涢幘瀵哥畾闁圭瓔鍋勯埞鎴︽倷閸欏娅ф繝鐢靛亹閸嬫捇姊洪崫鍕拱闁烩晩鍨堕悰顕€宕堕鈧悡娑樏归敐鍛棌闁诲骸纾槐鎾诲磼濮橆兘鍋撻崫銉х煋鐎规洖娲﹂鑺ユ叏濮楀棗澧绘繛鍏肩墬缁绘稑顔忛鑽ょ泿缂備胶濮烽弫濠氬蓟閻斿吋鍊绘俊顖滃劦閹疯顪冮妶鍡樼叆婵炲樊鍘奸～蹇涙惞鐟欏嫬鐝伴梺鐐藉劥濞呮洟鎮樺鍛斀闁绘劖褰冪痪褔鏌ㄥ顓滀簻妞ゆ挾鍋炴径鍕磼缂佹绠撴い顐ｇ箞椤㈡宕掑锝呬壕闁绘劗鍎ら埛鎴︽⒒閸喍绶遍柣鎿冨幘缁辨帡鎮╅崘鑼紘濡?")
	fs.StringVar(&value, "value", "", "闂佸湱顭堥ˇ閬嶇嵁閸℃ɑ娅犻柛鎰╁妼缂嶄線姊洪幓鎺旂闁逞屽墲婢瑰牏鎹㈤崘顭戠叆")
	fs.StringVar(&user, "user", "", "闂佸湱顭堥ˇ閬嶅极閵堝绠ｉ柣銈庡灣缁犳牗绻?")
	fs.Var(&sysEnv, "sysEnv", "Filter by system environment variable flag (true/false)")
	fs.Var(&output, "output", "闂傚倸鍊搁崐椋庣矆娓氣偓楠炴牠顢曚綅閸ヮ剦鏁嶉柣鎰綑娴滆鲸绻濋悽闈浶㈡繛灞傚€楃划缁樺鐎涙鍘甸梻鍌氬€搁顓⑺囬敃鍌涚厱婵ɑ鍓氬鎰版煏閸パ冾伃妤犵偞锕㈠畷锟犳倷閸忓憡鍋呴梻鍌欑閹诧繝宕濊箛娑樼；闁瑰墽绮埛鎺懨归敐鍫燁仩閻㈩垱鐩弻鐔煎传閵夘喚鍔搁梻鍥ь槸椤啰鈧綆浜滈銏ゆ煕韫囨梻鐭掗柡灞界Х椤т線鏌涢幘璺烘瀻妞ゎ偄绻愮叅妞ゅ繐瀚鍥煙閼圭増褰х紒鑼劋閹便劑宕惰濞撳鏌曢崼婵囶棞濞ｅ浂鍨辨穱濠囨嚑椤戣棄浜炬慨?闂?excel")
	fs.StringVar(&opts.ExcelPath, "excel", "", "闁诲海鏁搁崢褔宕?Excel 闂佸搫鍊稿ú锝呪枎閵忋垺宕夋い鏍ㄦ皑缁愮偤鏌?xlsx闂?")

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
		return opts, fmt.Errorf("output 闂傚倸鍊搁崐鎼佸磹妞嬪海鐭嗗〒姘ｅ亾妤犵偛顦甸弫鎾绘偐閸愯弓鐢婚梻渚€娼чˇ顐﹀疾濞戞艾顥氶柛锔诲幗閸犳劙鏌ｅΔ鈧悧鍡欑箔閹烘挻鍙忛悷娆忓閸欌偓闂佸搫鐭夌紞浣割嚕椤曗偓瀹曟帒顫濋璺ㄥ笡缂傚倸鍊风欢锟犲磻閸曨厾鐭撶憸鐗堝笒閽冪喖鏌ㄥ┑鍡樺晵闁绘梻鍘х粻浼村箹鏉堝墽鍒版繛鎳峰嫮绡€? %s", output.value)
	}
	if opts.OutputFormat == "excel" && strings.TrimSpace(opts.ExcelPath) == "" {
		return opts, fmt.Errorf("濠电偠鎻紞鈧繛澶嬫礋瀵?output=excel 闂備礁鎼崯鍐测枖濞戞碍宕查柍褜鍓欓—鍐Χ閸モ晛绗￠悷婊堫暒閻掞妇绮?-excel 闂備礁鎼崐绋棵洪敐鍛瀻闁靛繈鍨哄畷澶嬨亜閺嶃劍鐨戠紒?")
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
		fmt.Fprintln(os.Stderr, "闂傚倸鍊搁崐鎼佸磹閻戣姤鍊块柨鏇楀亾妞ゎ亜鍟村畷褰掝敋閸涱垰濮洪梻浣侯潒閸曞灚鐣剁紓浣插亾濠㈣泛澶囬崑鎾荤嵁閸喖濮庡┑鐐额嚋缁犳挸鐣?")
		fmt.Fprintln(os.Stderr, "  c-eyes kernel-scan [闂傚倸鍊搁崐鎼佸磹妞嬪海鐭嗗〒姘ｅ亾妤犵偛顦甸弫鎾绘偐閸愯弓鐢婚梻渚€娼чˇ顐﹀疾濞戞艾顥氶柛锔诲幗閸犳劙鏌ｅΔ鈧悧鍡欑箔閹烘挻鍙忛悷娆忓閸欌偓闂?[-output json|excel] [-excel out.xlsx]")
		fmt.Fprintln(os.Stderr, "\n闂傚倸鍊搁崐鎼佸磹妞嬪海鐭嗗〒姘ｅ亾妤犵偛顦甸弫鎾绘偐閸愯弓鐢婚梻渚€娼чˇ顐﹀疾濞戞艾顥氶柛锔诲幗閸犳劙鏌ｅΔ鈧悧鍡欑箔閹烘挻鍙?")
		fs.PrintDefaults()
	}

	var opts kernelScanOptions
	var hostname, ip, moduleName, path string
	var groups intSliceFlag
	var version stringSliceFlag
	output := outputModeFlag{value: "json"}

	fs.Var(&groups, "groups", "闂備礁婀遍…鍫ニ囨潏鈺佸灊?ID 闂佸搫顦弲娑樏洪敃鍌氱闁靛牆顦伴弲顒傗偓鍏夊亾闁告洏鍔屾禍鐐繆閵堝倸浜鹃悷婊勬緲濞尖€崇暦濮樿泛骞㈡繛鎴炵懐閸?")
	fs.StringVar(&hostname, "hostname", "", "闂備礁婀遍…鍫ニ囬閿亾闂堟稓鐒哥€殿喚鏁诲畷顐﹀礋椤掆偓閳ь剚濞婂鍫曞煛娴ｇ懓顦╅梺?")
	fs.StringVar(&ip, "ip", "", "闂?IP 闂佸搫顦弲娑樏洪敃鍌氱")
	fs.StringVar(&moduleName, "moduleName", "", "闂佸湱顭堥ˇ鎷屽暞闂佺鍕垫當闁诡喗娲滅划鏃堝箯瀹€鈧粻鏍ㄧ節?")
	fs.StringVar(&path, "path", "", "闂佸湱顭堥ˇ鎷屽暞闂佺鍕垫畽闁活厽鍎抽銉╁礋椤斿墽鐣哄┑?")
	fs.Var(&version, "version", "闂佸湱顭堥ˇ鎷屽暞闂佺鍕垫畼濠⒀勵殜瀵敻顢楅崘顏嗙暫濠电姴顭堥崐褏妲愬┑瀣劵婵°倐鍋撶憸鏉挎健瀹曟岸宕卞☉娆樺悩")
	fs.Var(&output, "output", "闂傚倸鍊搁崐椋庣矆娓氣偓楠炴牠顢曚綅閸ヮ剦鏁嶉柣鎰綑娴滆鲸绻濋悽闈浶㈡繛灞傚€楃划缁樺鐎涙鍘甸梻鍌氬€搁顓⑺囬敃鍌涚厱婵ɑ鍓氬鎰版煏閸パ冾伃妤犵偞锕㈠畷锟犳倷閸忓憡鍋呴梻鍌欑閹诧繝宕濊箛娑樼；闁瑰墽绮埛鎺懨归敐鍫燁仩閻㈩垱鐩弻鐔煎传閵夘喚鍔搁梻鍥ь槸椤啰鈧綆浜滈銏ゆ煕韫囨梻鐭掗柡灞界Х椤т線鏌涢幘璺烘瀻妞ゎ偄绻愮叅妞ゅ繐瀚鍥煙閼圭増褰х紒鑼劋閹便劑宕惰濞撳鏌曢崼婵囶棞濞ｅ浂鍨辨穱濠囨嚑椤戣棄浜炬慨?闂?excel")
	fs.StringVar(&opts.ExcelPath, "excel", "", "闁诲海鏁搁崢褔宕?Excel 闂佸搫鍊稿ú锝呪枎閵忋垺宕夋い鏍ㄦ皑缁愮偤鏌?xlsx闂?")

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
		return opts, fmt.Errorf("output 闂傚倸鍊搁崐鎼佸磹妞嬪海鐭嗗〒姘ｅ亾妤犵偛顦甸弫鎾绘偐閸愯弓鐢婚梻渚€娼чˇ顐﹀疾濞戞艾顥氶柛锔诲幗閸犳劙鏌ｅΔ鈧悧鍡欑箔閹烘挻鍙忛悷娆忓閸欌偓闂佸搫鐭夌紞浣割嚕椤曗偓瀹曟帒顫濋璺ㄥ笡缂傚倸鍊风欢锟犲磻閸曨厾鐭撶憸鐗堝笒閽冪喖鏌ㄥ┑鍡樺晵闁绘梻鍘х粻浼村箹鏉堝墽鍒版繛鎳峰嫮绡€? %s", output.value)
	}
	if opts.OutputFormat == "excel" && strings.TrimSpace(opts.ExcelPath) == "" {
		return opts, fmt.Errorf("濠电偠鎻紞鈧繛澶嬫礋瀵?output=excel 闂備礁鎼崯鍐测枖濞戞碍宕查柍褜鍓欓—鍐Χ閸モ晛绗￠悷婊堫暒閻掞妇绮?-excel 闂備礁鎼崐绋棵洪敐鍛瀻闁靛繈鍨哄畷澶嬨亜閺嶃劍鐨戠紒?")
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
		fmt.Fprintln(os.Stderr, "  -yara-rules <path>                        Yara rule path")
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
			fmt.Fprintln(os.Stderr, "mode=hybrid 閺嗗倹婀弨顖涘瘮閿涘矁鍤滈崝銊╂缁狙傝礋 mode=smart")
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
				fmt.Fprintln(os.Stderr, "閺堫亝澹橀崚鏉垮讲閻劎娈?YARA 鐟欏嫬鍨弬鍥︽")
				os.Exit(2)
			}
			fmt.Fprintln(os.Stderr, "Hint: no YARA rule provided, skipping local matching")
		}
		if rules != "" {
			engine, err := riskanalysis.NewYaraXEngine(riskanalysis.YaraXConfig{
				RulesPath:     rules,
				ReadChunkSize: opts.YaraReadChunk,
			})
			if err != nil {
				if mode == riskanalysis.ModeLocalOnly {
					fmt.Fprintf(os.Stderr, "\u672c\u5730 YARA \u5f15\u64ce\u521d\u59cb\u5316\u5931\u8d25: %v\n", err)
					os.Exit(2)
				}
				fmt.Fprintf(os.Stderr, "\u672c\u5730 YARA \u5f15\u64ce\u521d\u59cb\u5316\u5931\u8d25: %v\n", err)
			} else {
				if warning := riskanalysis.YaraXEngineWarning(engine); warning != "" {
					if mode == riskanalysis.ModeLocalOnly {
						fmt.Fprintf(os.Stderr, "\u672c\u5730 YARA \u5f15\u64ce\u8b66\u544a: %s\n", warning)
						os.Exit(2)
					}
					fmt.Fprintf(os.Stderr, "\u672c\u5730 YARA \u5f15\u64ce\u8b66\u544a: %s\n", warning)
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
				fmt.Fprintf(os.Stderr, "\u52a0\u8f7d\u4e91\u914d\u7f6e\u5931\u8d25\uff08%s\uff09: %v\n", cfgPath, cfgErr)
			} else {
				fmt.Fprintf(os.Stderr, "\u52a0\u8f7d\u4e91\u914d\u7f6e\u5931\u8d25: %v\n", cfgErr)
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
					fmt.Fprintf(os.Stderr, "\u4e91\u7aef provider %s \u7684 rate-limit \u914d\u7f6e\u65e0\u6548: %v\n", provider, err)
				} else {
					rateLimit = d
				}
			}
			if opts.CloudUpload && providerCfg.UploadRateLimit != "" {
				if d, err := providerCfg.UploadRateLimitDuration(); err != nil {
					fmt.Fprintf(os.Stderr, "\u4e91\u7aef provider %s \u7684\u4e0a\u4f20 rate-limit \u914d\u7f6e\u65e0\u6548: %v\n", provider, err)
				} else {
					rateLimit = d
				}
			}

			timeout := 10 * time.Second
			if providerCfg.Timeout != "" {
				if d, err := providerCfg.TimeoutDuration(); err != nil {
					fmt.Fprintf(os.Stderr, "\u4e91\u7aef provider %s \u7684 timeout \u914d\u7f6e\u65e0\u6548: %v\n", provider, err)
				} else {
					timeout = d
				}
			}

			cacheTTL := 10 * time.Minute
			if providerCfg.CacheTTL != "" {
				if d, err := providerCfg.CacheTTLDuration(); err != nil {
					fmt.Fprintf(os.Stderr, "\u4e91\u7aef provider %s \u7684 cache-ttl \u914d\u7f6e\u65e0\u6548: %v\n", provider, err)
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
				fmt.Fprintf(os.Stderr, "\u521d\u59cb\u5316\u4e91 provider %s \u5931\u8d25: %v\n", provider, err)
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
		fmt.Fprintf(os.Stderr, "\u521d\u59cb\u5316\u6743\u5a01\u54c8\u5e0c\u4ed3\u5e93\u5931\u8d25: %v\n", hashRepoErr)
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
		fmt.Fprintln(os.Stderr, "闂傚倸鍊搁崐鎼佸磹閻戣姤鍊块柨鏇楀亾妞ゎ亜鍟村畷褰掝敋閸涱垰濮洪梻浣侯潒閸曞灚鐣剁紓浣插亾濠㈣泛澶囬崑鎾荤嵁閸喖濮庡┑鐐额嚋缁犳挸鐣?")
		fmt.Fprintln(os.Stderr, "  c-eyes file scan -mode [full|path|smart] [-path 闂傚倸鍊搁崐鎼佸磹閻戣姤鍤勯柛顐ｆ礀绾惧潡鏌ｉ姀銏╃劸闁汇倝绠栭弻宥夊传閸曨剙娅ｇ紓浣瑰姈椤ㄥ棙绌辨繝鍥ч柛娑卞枛濞呫倝姊虹粙娆惧剰妞わ妇鏁诲濠氬Ω閵夈垺鏂€闂佺硶鍓濋敋妞わ腹鏅犻幃妤冩喆閸曨剛顦ュ銈忕細閸楄櫕淇婇悽绋跨妞ゆ牗鑹鹃崬銊╂⒑闂堟侗鐓┑鈥虫搐閳绘捇濡堕崶鈺冿紳婵炶揪绲块幊鎾存叏婢舵劖鐓?[-excel out.xlsx]")
		fmt.Fprintln(os.Stderr, "\n闂傚倸鍊搁崐鎼佸磹妞嬪海鐭嗗〒姘ｅ亾妤犵偛顦甸弫鎾绘偐閸愯弓鐢婚梻渚€娼чˇ顐﹀疾濞戞艾顥氶柛锔诲幗閸犳劙鏌ｅΔ鈧悧鍡欑箔閹烘挻鍙?")
		fs.PrintDefaults()
	}

	var opts fileScanOptions
	var mode string
	var maxTargets int
	fs.StringVar(&mode, "mode", "smart", "闂傚倸鍊搁崐鎼佸磹瀹勬噴褰掑炊椤掑﹦绋忔繝銏ｅ煐閸旓箓寮繝鍥ㄧ厸鐎广儱楠搁獮鏍棯閹岀吋闁哄本绋戦埥澶愬础閻愭彃顒滈梻浣规偠閸婃牕煤閻旂厧钃熸繛鎴旀噰閳ь剨绠撻獮瀣攽閸ャ劎鏋冮梻鍌欒兌缁垰顫忔繝姘偍鐟滄棃骞冨Ο铏规殾闁搞儻绲芥禍楣冩偡濞嗗繐顏紒鈧埀顒€鈹戦悙鑼勾闁告梹鍨挎俊瀛樼瑹閳ь剙鐣烽妸褉鍋撳☉娅辨岸骞忓ú顏呪拺闁革富鍙庨悞鐐箾鐎电鍘撮柛鈺侊躬瀵挳濮€閿涘嫬骞楅梻浣瑰缁嬫垹鈧凹鍠楃粋鎺椼€傞幎锝夋⒒閸屾艾鈧悂宕愭搴㈩偨婵﹩鍓﹂悞鐣屾喐瀹ュ牏浜遍梻浣告惈閸燁偊鎮ч崱娑樺瀭闁稿本绋忔禍婊堟煥濠靛棙鍣烘い搴㈡尝 闂?smart")
	fs.StringVar(&opts.Path, "path", "", "闁?mode=path 闂備礁鎼崯鎶藉春閺嶎偀鍋撻崹顐ｇ殤闁逞屽墲椤鍠婂澶婂嚑闁告劏鏅濋々鐑芥煠閹间焦娑ч柣蹇旑殜閺岋綁鍩℃繝鍌涚亪缂傚倸绉寸粔鍫曞箲閸曨垼鏁嶆慨妯夸含閻?")
	fs.StringVar(&opts.ExcelPath, "excel", "", "闁诲海鏁搁崢褔宕?Excel 闂佸搫鍊稿ú锝呪枎閵忋垺宕夋い鏍ㄦ皑缁愮偤鏌?xlsx闂?")
	fs.IntVar(&maxTargets, "maxTargets", 0, "maximum targets to scan (0 means unlimited)")

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
		return opts, fmt.Errorf("mode 闂傚倸鍊搁崐鎼佸磹妞嬪海鐭嗗〒姘ｅ亾妤犵偛顦甸弫鎾绘偐閸愯弓鐢婚梻渚€娼чˇ顐﹀疾濞戞艾顥氶柛锔诲幗閸犳劙鏌ｅΔ鈧悧鍡欑箔閹烘挻鍙忛悷娆忓閸欌偓闂佸搫鐭夌紞浣割嚕椤曗偓瀹曟帒顫濋璺ㄥ笡缂傚倸鍊风欢锟犲磻閸曨厾鐭撶憸鐗堝笒閽冪喖鏌ㄥ┑鍡樺晵闁绘梻鍘х粻浼村箹鏉堝墽鍒版繛鎳峰嫮绡€? %s", mode)
	}

	if opts.Mode == filescan.ScanModePath && opts.Path == "" {
		return opts, fmt.Errorf("mode=path 闂傚倸鍊搁崐鎼佸磹妞嬪海鐭嗗〒姘ｅ亾妤犵偞鐗犻、鏇㈡晝閳ь剟鎮块鈧弻娑㈠箛椤撶姰鍋為梺鍝勵儐閻楁鎹㈠☉銏犵闁绘劖顔栭弳锟犳倵鐟欏嫭绀冮柣鎿勭節瀵顓奸崼顐ｎ€囬梻浣告啞閹稿鎮烽埡鍛伋闁哄啫鐗嗙粈鍐┿亜閺傛寧顫嶇憸鏃堝蓟濞戙垹唯闁靛繆鍓濋悵鏃傜磽娴ｈ娈ｇ紒缁樼箞楠炲啫鐣￠柇锔惧弳闂佸壊鍋掗崑鍛枔閵夆晜鈷戠紓浣姑柌婊冣攽閳ヨ櫕宸濋柛?-path")
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
