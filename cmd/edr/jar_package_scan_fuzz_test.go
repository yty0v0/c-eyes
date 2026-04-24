package main

import (
	"strconv"
	"testing"
)

func FuzzParseJarPackageScanFlagsNoPanic(f *testing.F) {
	f.Add("spring-core-6.1.2.jar", "6.1.2", "/opt/tomcat/lib/spring-core-6.1.2.jar", 3, false)
	f.Add("core.jar", "1.0.0", `C:\apps\core.jar`, 1, true)
	f.Add("", "", "", 9, false)

	f.Fuzz(func(t *testing.T, name, version, path string, typ int, executable bool) {
		typeVal := typ
		if typeVal < 0 {
			typeVal = -typeVal
		}
		typeVal = []int{1, 2, 3, 8, 9}[typeVal%5]

		args := []string{
			"-name", name,
			"-version", version,
			"-type", strconv.Itoa(typeVal),
			"-executable", strconv.FormatBool(executable),
			"-path", path,
		}
		_, _ = parseJarPackageScanFlags(args)
	})
}
