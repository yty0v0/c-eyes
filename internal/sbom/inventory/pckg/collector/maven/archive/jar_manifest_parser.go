
// Copyright (c) 2023 Jingdong Technology Information Technology Co., Ltd.
// SBOM-TOOL is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

package archive

import (
	"bufio"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/package-url/packageurl-go"

	"edrsystem/internal/sbom/model"
	"edrsystem/internal/sbom/util/license"
	"edrsystem/internal/sbom/util/log"
	"edrsystem/internal/sbom/util/ziputil"
)

const manifestFile = "META-INF/MANIFEST.MF"

var licFileNames = []string{
	"li[cs]en[cs]e(s?)",
	"copy(left|right|ing)",
	"bsd",
	"mit",
	"apache",
	"legal",
	"l?gpl([-_ v]?)(\\d\\.?\\d)?",
}

var licFileRe = regexp.MustCompile(
	fmt.Sprintf("^(|.*[-_. ])(%s)(|[-_. ].*)$",
		strings.Join(licFileNames, "|")))

type JarManifest struct {
	MainSection        map[string]string
	IndividualSections map[string]map[string]string
}

type Manifest map[string]string

func DiscoverMainPackage(path string) (*model.Package, error) {
	text, err := ziputil.GetTextFromZip(path, manifestFile)
	if err != nil {
		log.Errorf("get jar manifest error: %v", err)
	}
	log.Debugf("parse jar manifest")
	manifest, err := parseJarManifest(text)
	if err != nil {
		log.Errorf("parse jar manifest error: %v", err)
	}

	licenseDeclaredList := resolveLicense(manifest.MainSection)
	// 鎵弿jar鍖呭唴鏄惁瀛樺湪license鐩稿叧鏂囦欢锛岃幏鍙杔icense鎵弿缁撴灉
	licenseConcludedList := license.GetLicenseByZipFile(path)

	if len(licenseDeclaredList) == 0 {
		licenseDeclaredList = licenseConcludedList
	}
	// get name and version from FileName firstly.
	filenameObj := parseJavaArchiveFilename(path)
	name := filenameObj.name
	version := filenameObj.version
	if name == "" {
		name = resolveName(manifest.MainSection)
	}
	if version == "" {
		version = resolveVersion(manifest.MainSection)
	}
	// TODO call newPackage
	pkg := &model.Package{
		Name:             name,
		Version:          version,
		Type:             model.PkgTypeMaven,
		PURL:             buildPURL(name, version),
		LicenseDeclared:  licenseDeclaredList,
		LicenseConcluded: licenseConcludedList,
		SourceLocation:   path,
	}
	return pkg, nil
}

func buildPURL(name, version string) string {
	namespace, pkgName := splitNamespace(name)
	return packageurl.NewPackageURL(model.PkgTypeMaven, namespace, pkgName, version, nil, "").String()
}

func splitNamespace(name string) (string, string) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return "", ""
	}
	idx := strings.LastIndex(trimmed, "/")
	if idx <= 0 || idx >= len(trimmed)-1 {
		return "", trimmed
	}
	return trimmed[:idx], trimmed[idx+1:]
}

func parseJarManifest(content string) (*JarManifest, error) {
	var manifest JarManifest
	var sections []map[string]string

	currentSection := func() int {
		return len(sections) - 1
	}

	var lastKey string
	scanner := bufio.NewScanner(strings.NewReader(content))

	for scanner.Scan() {
		line := scanner.Text()

		// empty lines denote section separators
		if strings.TrimSpace(line) == "" {
			// we don't want to allocate a new section map that won't necessarily be used, do that once there is
			// a non-empty line to process

			// do not process line continuations after this
			lastKey = ""

			continue
		}

		if line[0] == ' ' {
			// this is a continuation

			if lastKey == "" {
				// log.Warnf("java manifest %q: found continuation with no previous key: %q", path, line)
				continue
			}

			sections[currentSection()][lastKey] += strings.TrimSpace(line)

			continue
		}

		// this is a new key-value pair
		idx := strings.Index(line, ":")
		if idx == -1 {
			// log.Warnf("java manifest %q: unable to split java manifest key-value pairs: %q", path, line)
			continue
		}

		key := strings.TrimSpace(line[0:idx])
		value := strings.TrimSpace(line[idx+1:])

		if key == "" {
			// don't attempt to add new keys or sections unless there is a non-empty key
			continue
		}

		if lastKey == "" {
			// we're entering a new section
			sections = append(sections, make(map[string]string))
		}

		sections[currentSection()][key] = value

		// keep track of key for potential future continuations
		lastKey = key
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("unable to read java manifest: %w", err)
	}

	if len(sections) > 0 {
		manifest.MainSection = sections[0]
		if len(sections) > 1 {
			manifest.IndividualSections = make(map[string]map[string]string)
			for i, s := range sections[1:] {
				name, ok := s["Name"]
				if !ok {
					// per the manifest spec (https://docs.oracle.com/en/java/javase/11/docs/specs/jar/jar.html#jar-manifest)
					// this should never happen. If it does, we want to know about it, but not necessarily stop
					// cataloging entirely... for this reason we only log.
					// log.Warnf("java manifest section found without a name: %s", path)
					name = strconv.Itoa(i)
				} else {
					delete(s, "Name")
				}
				manifest.IndividualSections[name] = s
			}
		}
	}

	return &manifest, nil
}

func resolveName(manifest Manifest) string {
	fields := []string{"Name", "Bundle-Name", "Short-Name", "Extension-Name", "Implementation-Title"}
	for _, key := range fields {
		if v := manifest[key]; v != "" {
			return manifest[key]
		}
	}
	return ""
}

func resolveVersion(manifest Manifest) string {
	fields := []string{"Implementation-Version", "Specification-Version", "Plugin-Version", "Bundle-Version"}
	for _, key := range fields {
		if v := manifest[key]; v != "" {
			return v
		}
	}
	return ""
}

func resolveLicense(manifest Manifest) []string {
	licenses := make([]string, 0)
	field := "Bundle-License"
	if v := manifest[field]; v != "" {
		arr := strings.Split(manifest[field], ",")
		for _, l := range arr {
			result, _, _ := license.ParseLicenseURL(l)
			if result != "" {
				licenses = license.SplitLicense(result, licenses)
			}
		}
	}

	return license.UniqueStrings(licenses)
}

