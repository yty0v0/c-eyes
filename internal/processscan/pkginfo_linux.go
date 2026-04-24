//go:build linux

package processscan

import (
	"bufio"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"

	rpmdb "github.com/knqyf263/go-rpmdb/pkg"
)

type pkgInfo struct {
	name    string
	version string
}

var pkgOnce sync.Once
var pkgByPath map[string]pkgInfo

// 对外查询入口，给定可执行文件路径，返回包名/版本/是否命中
func lookupPackageForPath(path string) (string, string, bool) {
	loadPackages()
	if info, ok := pkgByPath[path]; ok {
		return info.name, info.version, true
	}
	return "", "", false
}

// 只执行一次的初始化，加载 dpkg + rpm 数据库并构建路径映射
func loadPackages() {
	pkgOnce.Do(func() {
		pkgByPath = make(map[string]pkgInfo)
		versions := readDpkgStatus()
		loadDpkgLists(versions)
		loadRpmdb()
	})
}

// 读取 /var/lib/dpkg/status，得到 “包名 → 版本” 的映射
func readDpkgStatus() map[string]string {
	versions := make(map[string]string)
	file, err := os.Open("/var/lib/dpkg/status")
	if err != nil {
		return versions
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var currentPkg string
	var currentVer string
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if currentPkg != "" {
				versions[currentPkg] = currentVer
			}
			currentPkg = ""
			currentVer = ""
			continue
		}
		if strings.HasPrefix(line, "Package:") {
			currentPkg = strings.TrimSpace(strings.TrimPrefix(line, "Package:"))
		}
		if strings.HasPrefix(line, "Version:") {
			currentVer = strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
		}
	}
	if currentPkg != "" {
		versions[currentPkg] = currentVer
	}
	return versions
}

// 读取 /var/lib/dpkg/info/*.list，把包里包含的文件路径映射到包名/版本。
func loadDpkgLists(versions map[string]string) {
	listFiles, err := filepath.Glob("/var/lib/dpkg/info/*.list")
	if err != nil {
		return
	}
	for _, listFile := range listFiles {
		pkg := strings.TrimSuffix(filepath.Base(listFile), ".list")
		ver := versions[pkg]
		file, err := os.Open(listFile)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			path := strings.TrimSpace(scanner.Text())
			if path == "" {
				continue
			}
			if _, exists := pkgByPath[path]; !exists {
				pkgByPath[path] = pkgInfo{name: pkg, version: ver}
			}
		}
		file.Close()
	}
}

// 尝试打开 rpmdb（可能是 Berkeley DB 或 sqlite），读取包列表并建映射
func loadRpmdb() {
	paths := []string{
		"/var/lib/rpm/Packages",
		"/usr/lib/sysimage/rpm/Packages",
		"/var/lib/rpm/rpmdb.sqlite",
		"/usr/lib/sysimage/rpm/rpmdb.sqlite",
	}

	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		db, err := rpmdb.Open(path)
		if err != nil {
			continue
		}
		pkgs, err := db.ListPackages()
		if err == nil {
			mapRpmPackages(pkgs)
		}
		_ = db.Close()
		if len(pkgByPath) > 0 {
			break
		}
	}
}

// 从 rpm 包列表中提取包名/版本/文件路径，填充 “路径 → 包信息”
func mapRpmPackages(pkgs any) {
	value := reflect.ValueOf(pkgs)
	if value.Kind() != reflect.Slice {
		return
	}

	for i := 0; i < value.Len(); i++ {
		pkg := value.Index(i).Interface()
		name := getStringField(pkg, "Name")
		version := getStringField(pkg, "Version")
		release := getStringField(pkg, "Release")
		if release != "" {
			if version != "" {
				version = version + "-" + release
			} else {
				version = release
			}
		}

		files := getStringSliceField(pkg, "FileNames")
		if len(files) == 0 {
			files = callStringSliceMethod(pkg, "FileNames")
		}
		if len(files) == 0 {
			files = getStringSliceField(pkg, "Files")
		}
		if len(files) == 0 {
			files = callStringSliceMethod(pkg, "Files")
		}
		if len(files) == 0 {
			files = buildFileList(pkg)
		}

		for _, path := range files {
			if path == "" {
				continue
			}
			if _, exists := pkgByPath[path]; !exists {
				pkgByPath[path] = pkgInfo{name: name, version: version}
			}
		}
	}
}

// 从 rpm 包对象里用反射取字符串字段（如 Name、Version）
func getStringField(pkg any, name string) string {
	value := reflect.ValueOf(pkg)
	if value.Kind() == reflect.Pointer {
		value = value.Elem()
	}
	if value.Kind() != reflect.Struct {
		return ""
	}
	field := value.FieldByName(name)
	if !field.IsValid() || field.Kind() != reflect.String {
		return ""
	}
	return field.String()
}

// 用反射取字符串数组字段（如 FileNames）
func getStringSliceField(pkg any, name string) []string {
	value := reflect.ValueOf(pkg)
	if value.Kind() == reflect.Pointer {
		value = value.Elem()
	}
	if value.Kind() != reflect.Struct {
		return nil
	}
	field := value.FieldByName(name)
	if !field.IsValid() || field.Kind() != reflect.Slice {
		return nil
	}
	if field.Type().Elem().Kind() != reflect.String {
		return nil
	}
	out := make([]string, field.Len())
	for i := 0; i < field.Len(); i++ {
		out[i] = field.Index(i).String()
	}
	return out
}

// 用反射取整数数组字段（如 DirIndexes）
func getIntSliceField(pkg any, name string) []int {
	value := reflect.ValueOf(pkg)
	if value.Kind() == reflect.Pointer {
		value = value.Elem()
	}
	if value.Kind() != reflect.Struct {
		return nil
	}
	field := value.FieldByName(name)
	if !field.IsValid() || field.Kind() != reflect.Slice {
		return nil
	}
	out := make([]int, field.Len())
	for i := 0; i < field.Len(); i++ {
		elem := field.Index(i)
		switch elem.Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			out[i] = int(elem.Int())
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			out[i] = int(elem.Uint())
		default:
			return nil
		}
	}
	return out
}

// 尝试调用对象的方法（如 FileNames()/Files()）拿到字符串数组
func callStringSliceMethod(pkg any, name string) []string {
	value := reflect.ValueOf(pkg)
	method := value.MethodByName(name)
	if !method.IsValid() && value.Kind() != reflect.Pointer {
		ptr := reflect.New(value.Type())
		ptr.Elem().Set(value)
		method = ptr.MethodByName(name)
	}
	if !method.IsValid() {
		return nil
	}

	results := method.Call(nil)
	if len(results) == 0 {
		return nil
	}

	if len(results) > 1 {
		errType := reflect.TypeOf((*error)(nil)).Elem()
		if results[1].IsValid() && results[1].Type().Implements(errType) && !results[1].IsNil() {
			return nil
		}
	}

	list := results[0]
	if list.Kind() != reflect.Slice || list.Type().Elem().Kind() != reflect.String {
		return nil
	}
	out := make([]string, list.Len())
	for i := 0; i < list.Len(); i++ {
		out[i] = list.Index(i).String()
	}
	return out
}

// 从 DirNames + BaseNames + DirIndexes 组合出完整文件路径列表
func buildFileList(pkg any) []string {
	dirnames := getStringSliceField(pkg, "DirNames")
	basenames := getStringSliceField(pkg, "BaseNames")
	indexes := getIntSliceField(pkg, "DirIndexes")
	if len(dirnames) == 0 || len(basenames) == 0 || len(indexes) != len(basenames) {
		return nil
	}
	files := make([]string, 0, len(basenames))
	for i, base := range basenames {
		idx := indexes[i]
		if idx < 0 || idx >= len(dirnames) {
			continue
		}
		files = append(files, filepath.Join(dirnames[idx], base))
	}
	return files
}
