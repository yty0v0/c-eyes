
// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package pckg

import (
	"strings"

	"golang.org/x/exp/slices"

	"edrsystem/internal/sbom/inventory/pckg/collector"
	"edrsystem/internal/sbom/inventory/pckg/collector/bower"
	"edrsystem/internal/sbom/inventory/pckg/collector/cargo"
	"edrsystem/internal/sbom/inventory/pckg/collector/carthage"
	"edrsystem/internal/sbom/inventory/pckg/collector/cocoapods"
	"edrsystem/internal/sbom/inventory/pckg/collector/composer"
	"edrsystem/internal/sbom/inventory/pckg/collector/conan"
	"edrsystem/internal/sbom/inventory/pckg/collector/conda"
	"edrsystem/internal/sbom/inventory/pckg/collector/deb"
	"edrsystem/internal/sbom/inventory/pckg/collector/dylib"
	"edrsystem/internal/sbom/inventory/pckg/collector/gem"
	"edrsystem/internal/sbom/inventory/pckg/collector/golang"
	"edrsystem/internal/sbom/inventory/pckg/collector/lua"
	"edrsystem/internal/sbom/inventory/pckg/collector/maven"
	"edrsystem/internal/sbom/inventory/pckg/collector/npm"
	"edrsystem/internal/sbom/inventory/pckg/collector/nuget"
	"edrsystem/internal/sbom/inventory/pckg/collector/pub"
	"edrsystem/internal/sbom/inventory/pckg/collector/pypi"
	"edrsystem/internal/sbom/inventory/pckg/collector/rpm"
	"edrsystem/internal/sbom/inventory/pckg/collector/swift"
	"edrsystem/internal/sbom/util"
)

func AllCollectors() []collector.Collector {
	var allCollectors []collector.Collector
	allCollectors = append(allCollectors, bower.NewCollector())
	allCollectors = append(allCollectors, cargo.NewCollector())
	allCollectors = append(allCollectors, carthage.NewCollector())
	allCollectors = append(allCollectors, cocoapods.NewCollector())
	allCollectors = append(allCollectors, composer.NewCollector())
	allCollectors = append(allCollectors, conan.NewCollector())
	allCollectors = append(allCollectors, conda.NewCollector())
	allCollectors = append(allCollectors, gem.NewCollector())
	allCollectors = append(allCollectors, golang.NewCollector())
	allCollectors = append(allCollectors, lua.NewCollector())
	allCollectors = append(allCollectors, maven.NewCollector())
	allCollectors = append(allCollectors, npm.NewCollector())
	allCollectors = append(allCollectors, nuget.NewCollector())
	allCollectors = append(allCollectors, pub.NewCollector())
	allCollectors = append(allCollectors, pypi.NewCollector())
	allCollectors = append(allCollectors, rpm.NewCollector())
	allCollectors = append(allCollectors, swift.NewCollector())
	allCollectors = append(allCollectors, dylib.NewCollector())
	allCollectors = append(allCollectors, deb.NewCollector())
	return allCollectors
}

// GetCollectors groups for directory
func GetCollectors(names string) []collector.Collector {
	allCollectors := AllCollectors()
	names = strings.TrimSpace(names)
	if names == "" || names == "*" {
		return allCollectors
	}
	namesArr := strings.Split(names, ",")
	namesArr = util.SliceMap(namesArr, func(name string) string {
		return strings.TrimSpace(name)
	})
	namesArr = util.SliceFilter(namesArr, func(name string) bool {
		return name != ""
	})
	return util.SliceFilter(allCollectors, func(collector collector.Collector) bool {
		return slices.Contains(namesArr, collector.GetName())
	})
}

